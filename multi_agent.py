"""
Lab 5 (LLM-Powered): Multi-Agent LangGraph with LLM-based Supervisor
Author: Manas Dasgupta
Purpose: Demonstrate LangGraph orchestration where an LLM decides workflow steps
         while agents perform simulated cybersecurity reconnaissance tasks.
Goal of the Lab: Build a multi-agent system with an LLM supervisor that dynamically
                 determines the next steps based on intermediate results.
What the System does: 
- Simulates a reconnaissance workflow with multiple agents (Recon, OSINT, Report).
- An LLM supervisor node analyzes the current state and decides the next agent to invoke.                          
List of Inputs:
- Target IP or domain
- Initial scan parameters
- OSINT sources to query
"""

from typing import TypedDict
from langgraph.graph import StateGraph, START, END
from langchain_openai import ChatOpenAI
from datetime import datetime
import json, os
from dotenv import load_dotenv

load_dotenv()

# -----------------------------
# 1️⃣ Define State Schema
# -----------------------------
class ReconState(TypedDict):
    target: str                     # Target IP or domain
    scan_results: list              # List of discovered services
    osint_data: list                # List of OSINT enrichment data
    report: str                     # Final report summary
    logs: list                      # Event logs
    supervisor_reasoning: list      # Reasoning behind supervisor decisions

# -----------------------------
# 2️⃣ Define the LLM (Supervisor Brain)
# -----------------------------
llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)

def log_event(state, event):
    """Utility to append timestamped events."""
    ts = datetime.now().strftime("%H:%M:%S")
    state["logs"].append(f"[{ts}] {event}")
    print(f"[LOG] {event}")

# -----------------------------
# 3️⃣ Agent Nodes (Safe Simulations)
# -----------------------------
def recon_node(state: dict) -> dict:
    log_event(state, f"🛰️ Recon Agent: Scanning {state['target']} (simulated)")
    try:
        with open("logs/nmap_quick_scan.json", "r") as f:
            data = json.load(f)
            # Handle the file format which has an 'open_ports' list
            state["scan_results"] = data.get("open_ports", [])
    except FileNotFoundError:
        # Fallback to mock data if file not found
        state["scan_results"] = [
            {"port": 80, "service": "http"},
            {"port": 3306, "service": "mysql"}
        ]
        log_event(state, "Warning: Nmap scan file not found, using mock data")
    # Log each discovered service in detail
    count = len(state["scan_results"])
    log_event(state, f"Recon Agent: Found {count} open services.")
    for sr in state["scan_results"]:
        # Safe access with .get() and ensure port is string for consistency
        port = str(sr.get('port', 'unknown'))
        service = sr.get('service', 'unknown')
        status = sr.get('state', 'open')  # Default to 'open' if not specified
        log_event(state, f"Recon Agent Detail: port={port}, service={service}, state={status}")
    return state

def osint_node(state: dict) -> dict:
    log_event(state, "🌐 OSINT Agent: Enriching results (mock data).")
    try:
        with open("logs/osint_log.json", "r") as f:
            state["osint_data"] = json.load(f)
    except FileNotFoundError:
        # Fallback to mock data if file not found
        state["osint_data"] = [
            {"source": "Shodan", "info": "Internal training VM"},
            {"source": "Whois", "info": "No public record"}
        ]
        log_event(state, "Warning: OSINT log file not found, using mock data")
    # Log each enrichment entry for traceability
    log_event(state, f"OSINT Agent: Added {len(state['osint_data'])} enrichment entries.")
    for ent in state["osint_data"]:
        log_event(state, f"OSINT Detail: source={ent.get('source')}, info={ent.get('info')}")
    return state

def report_node(state: dict) -> dict:
    log_event(state, "🧾 Report Agent: Compiling final report.")
    summary = (
        f"Recon Report for {state['target']}: "
        f"{len(state['scan_results'])} open services, "
        f"{len(state['osint_data'])} enrichment records."
    )
    state["report"] = summary
    # Log the report summary and include key details for auditing
    log_event(state, f"Report Agent: Report completed. Summary: {summary}")
    # Optionally include the raw scan results and OSINT snippets in logs for deeper trace
    for sr in state.get("scan_results", []):
        log_event(state, f"Report Detail - Scan: port={sr.get('port')}, service={sr.get('service')}")
    for ent in state.get("osint_data", []):
        log_event(state, f"Report Detail - OSINT: source={ent.get('source')}, info={ent.get('info')}")
    return state

# -----------------------------
# 4️⃣ LLM-Powered Supervisor Logic
# -----------------------------
def supervisor_node(state: dict) -> dict:
    """LLM supervisor that decides next node with a built-in stop condition."""
    # ----- 1. Stop condition -----
    if state.get("report"):
        log_event(state, "🧠 Supervisor: Report already exists, ending workflow.")
        state["next_node"] = "end"
        return state

    # If scan results missing → recon first
    if not state.get("scan_results"):
        state["next_node"] = "recon"
        state["supervisor_reasoning"].append(
            {"next_node": "recon", "reason": "No scan results found yet."}
        )
        log_event(state, "🧠 Supervisor Decision: Next = recon | Reason = No scan results found.")
        return state

    # If OSINT missing → move to osint
    if not state.get("osint_data"):
        state["next_node"] = "osint"
        state["supervisor_reasoning"].append(
            {"next_node": "osint", "reason": "Recon complete, enrich with OSINT."}
        )
        log_event(state, "🧠 Supervisor Decision: Next = osint | Reason = Enrichment required.")
        return state

    # ----- 2. Ask the LLM only if needed -----
    reasoning_prompt = f"""
    You are a cybersecurity workflow supervisor.
    Target: {state['target']}
    Steps completed: recon={bool(state['scan_results'])}, osint={bool(state['osint_data'])}
    Report done: {bool(state['report'])}
    Choose next: recon, osint, report, or end.
    Return JSON: {{"next_node": "<choice>", "reason": "<why>"}}
    """
    response = llm.invoke(reasoning_prompt)
    decision_text = response.content.strip()
    try:
        decision = json.loads(decision_text)
    except Exception:
        decision = {"next_node": "report", "reason": "Defaulted to report step"}

    log_event(
        state,
        f"🧠 Supervisor Decision: Next = {decision['next_node']} | Reason = {decision['reason']}"
    )
    state["supervisor_reasoning"].append(decision)
    state["next_node"] = decision["next_node"]
    return state

# -----------------------------
# 5️⃣ Build LangGraph
# -----------------------------
graph = StateGraph(ReconState)

# Add nodes
graph.add_node("supervisor", supervisor_node)
graph.add_node("recon", recon_node)
graph.add_node("osint", osint_node)
graph.add_node("report", report_node)

# Define dynamic flow (Supervisor always decides next)
graph.add_edge(START, "supervisor")
graph.add_conditional_edges(
    "supervisor",
    lambda state: state.get("next_node"),
    {
        "recon": "recon",
        "osint": "osint",
        "report": "report",
        "end": END,
    },
)
graph.add_edge("recon", "supervisor")
graph.add_edge("osint", "supervisor")
graph.add_edge("report", "supervisor")

# Compile
llm_graph = graph.compile()

# -----------------------------
# 6️⃣ Scenario Loader
# -----------------------------
def load_scenario(name: str = "default_full_pipeline") -> dict:
    with open("lab_scenarios.json", "r") as f:
        scenarios = json.load(f)
    if name not in scenarios:
        raise ValueError(f"Scenario '{name}' not found. Available: {list(scenarios.keys())}")
    return scenarios[name]

# -----------------------------
# 7️⃣ Run Simulation (Scenario-Based)
# -----------------------------
def supervisor_run(scenario_name: str = "default_full_pipeline"):
    config = load_scenario(scenario_name)

    print(f"\n🎯 Running scenario: {scenario_name}")
    print(f"    {config.get('description', '')}\n")

    # Initial state seeded from scenario
    state: ReconState = {
        "target": config["target"],
        "scan_results": config.get("scan_results", []),
        "osint_data": config.get("osint_data", []),
        "report": config.get("report", ""),
        "logs": [],
        "supervisor_reasoning": []
    }

    print("🧠 Starting LLM-Orchestrated LangGraph Run...\n")
    final_state = llm_graph.invoke(state)

    # Normalize final_state to a plain dict
    if hasattr(final_state, "dict") and callable(getattr(final_state, "dict", None)):
        out_obj = final_state.dict()
    elif isinstance(final_state, dict):
        out_obj = final_state
    else:
        try:
            out_obj = dict(final_state)
        except Exception:
            out_obj = {"report": getattr(final_state, "report", str(final_state))}

    os.makedirs("logs", exist_ok=True)
    log_path = f"logs/recon_lab_llm_{scenario_name}.json"
    with open(log_path, "w") as f:
        json.dump(out_obj, f, indent=2)

    print(f"\n✅ LLM Workflow Complete. Log saved to {log_path}")

    print("\n--- Final Report ---")
    print(out_obj.get("report", ""))

    print("\n--- Supervisor Reasoning Trace ---")
    for step in out_obj.get("supervisor_reasoning", []):
        print(f"{step['next_node'].upper()}: {step['reason']}")

    print("\n--- Log Events ---")
    for log in out_obj.get("logs", []):
        print(log)


if __name__ == "__main__":
    # Change scenario name here to test different flows
    supervisor_run("default_full_pipeline")
    #supervisor_run("recon_already_done")
    #supervisor_run("recon_and_osint_done")
    #supervisor_run("report_already_exists")
