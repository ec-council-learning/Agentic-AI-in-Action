"""
Lab 5: Purple Team Simulation (Log-based)
-----------------------------------------

This lab builds a multi-agent LangGraph that simulates a Purple Team scenario
using *external log files* as the primary data source.

Key ideas:
- GraphState is the single source of truth.
- Logs are ingested from disk (no hard-coded sample logs in this file).
- "Red" and "Blue" agents both reason over logs.
- Supervisor orchestrates which node runs next.
- Reporting produces a summary for learners/SOC analysts.

NOTE:
    You should create actual log files under ./logs or a
    directory of your choice. This script expects those files to exist.
"""

from __future__ import annotations

import os
from typing import TypedDict, List, Dict, Any, Optional

from langgraph.graph import StateGraph, START, END
# You can plug in an LLM if you want richer explanations.
# For now, logic is rule-based and diagnostic-print heavy.
# from langchain_openai import ChatOpenAI

# -----------------------------------------------------------------------------
# 1. Define the GraphState
# -----------------------------------------------------------------------------

class GraphState(TypedDict):
    """
    Shared state flowing through the graph.

    All nodes read and write from/to this structure.
    """
    # Raw log lines ingested from external log files.
    logs: List[str]

    # Inferred attacker actions (from the "Red" perspective).
    red_actions: List[Dict[str, Any]]

    # Alerts and findings from the "Blue" (defender) perspective.
    blue_alerts: List[Dict[str, Any]]

    # Human-readable narration of what happened (for teaching / SOC notes).
    conversation_history: List[str]

    # Supervisor's last decision about which node should run next.
    supervisor_decision: Optional[str]

    # Remaining log files to ingest (absolute or relative paths).
    remaining_log_files: List[str]

    # Count of log lines processed so far (for diagnostics).
    processed_logs: int

    # Termination flag for the simulation.
    done: bool


# -----------------------------------------------------------------------------
# 2. Helper: Discover log files on disk
# -----------------------------------------------------------------------------

def discover_log_files(log_dir: str) -> List[str]:
    """
    Walk a directory and return a list of .log files.

    This is called *before* running the graph, so the list of files can be
    placed into the initial GraphState.
    """
    log_files: List[str] = []

    print(f"[DISCOVER] Scanning for .log files under: {log_dir!r}")

    for root, _, files in os.walk(log_dir):
        for name in files:
            if name.lower().endswith(".log"):
                full_path = os.path.join(root, name)
                log_files.append(full_path)

    log_files = sorted(log_files)
    print(f"[DISCOVER] Found {len(log_files)} log file(s).")
    for path in log_files:
        print(f"           - {path}")

    return log_files


# -----------------------------------------------------------------------------
# 3. Node: IngestLogs (reads external files, populates `logs`)
# -----------------------------------------------------------------------------

def ingest_logs_node(state: GraphState) -> GraphState:
    """
    Ingest logs from the next file in `remaining_log_files` and append them
    into state["logs"].

    This node simulates pulling data from a log collector / SIEM.
    """

    print("\n[INGEST] Entering ingest_logs_node")
    remaining = state.get("remaining_log_files", [])

    if not remaining:
        print("[INGEST] No remaining log files to ingest.")
        state["conversation_history"].append(
            "IngestLogs: No more log files to process; moving on."
        )
        # Let the supervisor decide the next step (Red / Blue / Report).
        return state

    # Pop the next file to ingest.
    next_file = remaining.pop(0)
    print(f"[INGEST] Ingesting log file: {next_file}")

    try:
        with open(next_file, "r", encoding="utf-8") as f:
            new_lines = [line.rstrip("\n") for line in f]

        num_new = len(new_lines)
        state["logs"].extend(new_lines)
        state["processed_logs"] += num_new

        print(f"[INGEST] Read {num_new} line(s) from {next_file}.")
        print(f"[INGEST] Total logs in state: {len(state['logs'])}")

        state["conversation_history"].append(
            f"IngestLogs: Ingested {num_new} log lines from {os.path.basename(next_file)}."
        )

    except FileNotFoundError:
        print(f"[INGEST] ERROR: Log file not found: {next_file}")
        state["conversation_history"].append(
            f"IngestLogs: ERROR - could not read log file {next_file}."
        )

    # Update remaining files back into state.
    state["remaining_log_files"] = remaining
    return state


# -----------------------------------------------------------------------------
# 4. Node: Red_Agent (infers "attacker" actions from logs)
# -----------------------------------------------------------------------------

def red_agent_node(state: GraphState) -> GraphState:
    """
    The "Red" agent is not actually running Nmap here.
    Instead, it infers likely attacker actions from logs.

    For example, it can look for SQL injection patterns, suspicious paths,
    or tools like "sqlmap" in user agents or URLs.

    This keeps the lab *log-based* while still maintaining a Red vs Blue split.
    """

    print("\n[RED] Entering red_agent_node")
    logs = state.get("logs", [])
    existing_actions = state.get("red_actions", [])

    print(f"[RED] Currently {len(logs)} log line(s) in state.")
    print(f"[RED] Existing inferred red_actions: {len(existing_actions)}")

    # Very simple pattern-based inference. You can refine/extend this.
    attack_indicators = [
        "UNION SELECT",
        " OR 1=1",
        "/admin",
        "/phpmyadmin",
        "sqlmap",
        "/wp-admin",
        "/login.php"
    ]

    new_actions: List[Dict[str, Any]] = []

    for line in logs:
        # Skip if we've already processed this line into an action.
        if any(action.get("source_log") == line for action in existing_actions):
            continue

        # Look for known suspicious patterns.
        for indicator in attack_indicators:
            if indicator.lower() in line.lower():
                action = {
                    "source_log": line,
                    "indicator": indicator,
                    "description": "Potential attacker activity inferred from log line."
                }
                new_actions.append(action)
                print(f"[RED] Inferred red_action from log: {indicator!r} in line.")
                break  # Avoid multiple indicators per line for simplicity.

    if not new_actions:
        print("[RED] No new red_actions inferred from logs.")
        state["conversation_history"].append(
            "Red_Agent: No new suspicious attacker behavior inferred from logs."
        )
    else:
        existing_actions.extend(new_actions)
        state["red_actions"] = existing_actions
        state["conversation_history"].append(
            f"Red_Agent: Inferred {len(new_actions)} new attacker action(s) from logs."
        )
        print(f"[RED] Total red_actions after update: {len(existing_actions)}")

    return state


# -----------------------------------------------------------------------------
# 5. Node: Blue_Agent (creates alerts based on logs + red_actions)
# -----------------------------------------------------------------------------

def blue_agent_node(state: GraphState) -> GraphState:
    """
    The "Blue" agent represents the defender/SOC view.

    It reads logs and red_actions, then produces blue_alerts based on simple,
    transparent rules. In a more advanced version, this could use an LLM to
    generate richer narratives, but here we focus on rule-based clarity.
    """

    print("\n[BLUE] Entering blue_agent_node")

    logs = state.get("logs", [])
    red_actions = state.get("red_actions", [])
    blue_alerts = state.get("blue_alerts", [])

    print(f"[BLUE] Logs available: {len(logs)}")
    print(f"[BLUE] Inferred red_actions available: {len(red_actions)}")
    print(f"[BLUE] Existing blue_alerts: {len(blue_alerts)}")

    # Example rule set: tag severity based on type of indicator.
    for action in red_actions:
        source_log = action.get("source_log", "")
        indicator = action.get("indicator", "")

        # Avoid duplicating alerts for the same source log.
        if any(alert.get("source_log") == source_log for alert in blue_alerts):
            continue

        # Naive severity mapping.
        if "UNION SELECT" in indicator or " OR 1=1" in indicator:
            severity = "high"
            category = "SQL Injection"
        elif "/admin" in indicator or "/wp-admin" in indicator:
            severity = "medium"
            category = "Admin Interface Probing"
        elif "sqlmap" in indicator:
            severity = "high"
            category = "Automated Scanner"
        else:
            severity = "low"
            category = "Generic Suspicious Activity"

        alert = {
            "source_log": source_log,
            "indicator": indicator,
            "severity": severity,
            "category": category,
            "description": (
                f"Detected {category} with severity={severity} "
                f"based on indicator '{indicator}'."
            ),
        }
        blue_alerts.append(alert)
        print(f"[BLUE] Created alert: {category} ({severity})")

    state["blue_alerts"] = blue_alerts

    if blue_alerts:
        state["conversation_history"].append(
            f"Blue_Agent: Raised {len(blue_alerts)} total alert(s) based on logs and inferred attacker actions."
        )
    else:
        state["conversation_history"].append(
            "Blue_Agent: No alerts raised; no suspicious patterns found."
        )

    print(f"[BLUE] Total blue_alerts after update: {len(blue_alerts)}")
    return state


# -----------------------------------------------------------------------------
# 6. Node: Reporting (produces final summary)
# -----------------------------------------------------------------------------

def reporting_node(state: GraphState) -> GraphState:
    """
    The Reporting node reads the full GraphState and produces a concise
    chronological summary. In a real system, this might write to a ticketing
    system or export a structured incident report.
    """

    print("\n[REPORT] Entering reporting_node")

    num_logs = len(state.get("logs", []))
    num_red = len(state.get("red_actions", []))
    num_blue = len(state.get("blue_alerts", []))

    print(f"[REPORT] Logs: {num_logs}, Red actions: {num_red}, Blue alerts: {num_blue}")

    summary_lines = [
        "Reporting: Purple Team Simulation Summary",
        f"- Total logs ingested: {num_logs}",
        f"- Inferred attacker actions (red_actions): {num_red}",
        f"- Alerts raised (blue_alerts): {num_blue}",
        "",
        "High-level timeline:",
    ]

    # Append some details for teaching/debrief.
    if num_red:
        summary_lines.append("  * Attacker behavior inferred from logs:")
        for idx, action in enumerate(state["red_actions"], start=1):
            summary_lines.append(f"      {idx}. {action.get('description')}")

    if num_blue:
        summary_lines.append("  * Defender alerts generated:")
        for idx, alert in enumerate(state["blue_alerts"], start=1):
            summary_lines.append(
                f"      {idx}. [{alert.get('severity').upper()}] "
                f"{alert.get('category')} - {alert.get('description')}"
            )

    summary_text = "\n".join(summary_lines)
    print("[REPORT] Final summary:")
    print(summary_text)

    state["conversation_history"].append(summary_text)
    state["done"] = True
    state["supervisor_decision"] = "done"
    return state


# -----------------------------------------------------------------------------
# 7. Node: Supervisor (decides which node runs next)
# -----------------------------------------------------------------------------

def supervisor_node(state: GraphState) -> GraphState:
    """
    Supervisor inspects the current state and sets `supervisor_decision` to one
    of the following:

        - "ingest_logs"
        - "run_red"
        - "run_blue"
        - "report"
        - "done"

    The actual routing to nodes is handled by `route_from_supervisor`.
    """

    print("\n[SUPERVISOR] Entering supervisor_node")

    logs = state.get("logs", [])
    red_actions = state.get("red_actions", [])
    blue_alerts = state.get("blue_alerts", [])
    remaining = state.get("remaining_log_files", [])
    done = state.get("done", False)

    print(f"[SUPERVISOR] State snapshot:")
    print(f"    Logs: {len(logs)}")
    print(f"    Red actions: {len(red_actions)}")
    print(f"    Blue alerts: {len(blue_alerts)}")
    print(f"    Remaining log files: {len(remaining)}")
    print(f"    Done flag: {done}")

    if done:
        decision = "done"

    elif remaining:
        # If there are still log files left, keep ingesting.
        decision = "ingest_logs"

    elif logs and not red_actions:
        # Logs present, but no inferred attacker behavior yet.
        decision = "run_red"

    elif red_actions and not blue_alerts:
        # Attacker behavior inferred, but no alerts yet.
        decision = "run_blue"

    else:
        # No remaining files; logs, red_actions, and blue_alerts are in some
        # final state. Time to generate the report.
        decision = "report"

    state["supervisor_decision"] = decision
    state["conversation_history"].append(
        f"Supervisor: Decision set to '{decision}'."
    )
    print(f"[SUPERVISOR] Decision: {decision}")
    return state


# -----------------------------------------------------------------------------
# 8. Router: Conditional edges from Supervisor
# -----------------------------------------------------------------------------

def route_from_supervisor(state: GraphState) -> str:
    """
    LangGraph uses this function to decide which node to route to next
    after running the Supervisor node.
    """

    decision = state.get("supervisor_decision")
    print(f"[ROUTER] Routing based on supervisor_decision={decision!r}")

    if decision == "ingest_logs":
        return "ingest_logs"
    elif decision == "run_red":
        return "red_agent"
    elif decision == "run_blue":
        return "blue_agent"
    elif decision == "report":
        return "reporting"
    elif decision == "done":
        return END
    else:
        print("[ROUTER] WARNING: Unknown decision, ending graph.")
        return END


# -----------------------------------------------------------------------------
# 9. Build the graph
# -----------------------------------------------------------------------------

def build_graph() -> Any:
    """
    Construct and return a compiled LangGraph app that runs the simulation.
    """

    graph = StateGraph(GraphState)

    # Register nodes.
    graph.add_node("supervisor", supervisor_node)
    graph.add_node("ingest_logs", ingest_logs_node)
    graph.add_node("red_agent", red_agent_node)
    graph.add_node("blue_agent", blue_agent_node)
    graph.add_node("reporting", reporting_node)

    # Set entry point.
    graph.set_entry_point("supervisor")

    # After Supervisor, choose next node dynamically.
    graph.add_conditional_edges(
        "supervisor",
        route_from_supervisor,
        {
            "ingest_logs": "ingest_logs",
            "red_agent": "red_agent",
            "blue_agent": "blue_agent",
            "reporting": "reporting",
            END: END,
        },
    )

    # After each worker node, return to Supervisor for the next decision.
    graph.add_edge("ingest_logs", "supervisor")
    graph.add_edge("red_agent", "supervisor")
    graph.add_edge("blue_agent", "supervisor")

    # After Reporting, go straight to END.
    graph.add_edge("reporting", END)

    app = graph.compile()
    return app


# -----------------------------------------------------------------------------
# 10. Entry point / demo runner
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    """
    Example usage:

    1. Create a ./logs directory.
    2. Place one or more .log files inside it.
    3. Run this script.

    You should see:
    - DISCOVER phase listing log files.
    - Supervisor deciding the next node.
    - IngestLogs reading files.
    - Red_Agent inferring attacker actions from logs.
    - Blue_Agent raising alerts.
    - Reporting producing a final summary.
    """

    LOG_DIR = "./logs"  # Adjust to wherever you'll place your log files.

    log_files = discover_log_files(LOG_DIR)

    # Initialize the GraphState.
    initial_state: GraphState = {
        "logs": [],
        "red_actions": [],
        "blue_alerts": [],
        "conversation_history": [],
        "supervisor_decision": None,
        "remaining_log_files": log_files,
        "processed_logs": 0,
        "done": False,
    }

    app = build_graph()

    print("\n[MAIN] Starting Purple Team simulation graph...")
    final_state = app.invoke(initial_state)
    print("\n[MAIN] Graph execution complete.")

    print("\n[MAIN] Conversation history / narrative:")
    print("----------------------------------------------------------")
    for line in final_state["conversation_history"]:
        print(line)
    print("----------------------------------------------------------")

    print("[MAIN] Final counts:")
    print(f"   Logs: {len(final_state['logs'])}")
    print(f"   Red actions: {len(final_state['red_actions'])}")
    print(f"   Blue alerts: {len(final_state['blue_alerts'])}")
    print(f"   Done: {final_state['done']}")
