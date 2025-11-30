# Lab 5 (LLM-Powered): Multi-Agent LangGraph with LLM Supervisor

**Course:** Agentic AI for Cybersecurity  
**Lab Type:** Hands-on (Code + Log Analysis)  
**Goal:** Understand how a **multi-agent LangGraph** can be orchestrated by an **LLM-powered Supervisor**, using **simulated recon workflows** (no real scans).

---

## 1. Lab Overview

In this lab you will:

- Build and run a **LangGraph-based multi-agent system**.
- Use an **LLM (gpt-4o-mini)** as a **Supervisor** to decide which agent runs next.
- Keep all security actions **safe and reproducible** by:
  - Simulating recon, OSINT, and reporting steps.
  - Writing everything to structured **logfiles** instead of running real tools.
- Experiment with **different scenarios** using a JSON configuration file.

By the end of this lab, you should be able to:

- Explain how **State**, **Nodes**, and **Edges** work in LangGraph.
- Understand the **Supervisor Pattern** for multi-agent orchestration.
- Read a **reasoning trace** and logs to understand agent behaviour.

---

## 2. Files & Structure

This lab uses the following key files:

```text
.
├── multi_agent.py          # Main LangGraph + LLM Supervisor implementation
├── lab5_scenarios.json     # Scenario definitions (initial states)
└── logs/
    └── recon_lab_llm_<scenario>.json   # Generated logs per run
