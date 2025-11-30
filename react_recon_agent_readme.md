# LangChain ReAct Agent - Educational Lab

## What is ReAct?

**ReAct = Reasoning + Acting**

A ReAct agent alternates between:
1. **Reasoning** (thinking about what to do)
2. **Acting** (using tools to gather information)

## Quick Start
```bash
# 1. Generate sample log files
python react_recon_agent_generate_scan_logs.py

# 2. Run the ReAct agent
export OPENAI_API_KEY='your-key-here'
python recon_agent.py

# 3. Select a demo question
# Watch the agent reason and select tools!
```

## What You'll Learn

### Core Concepts

1. **Tool Selection** - How the agent chooses which tool to use
2. **Tool Chaining** - How the agent uses multiple tools in sequence
3. **Reasoning Process** - How the agent thinks between each action
4. **Autonomous Decision-Making** - Agent decides without you telling it

### The ReAct Loop
```
Question → Thought → Action → Observation → Thought → Action → ... → Final Answer
```

## Example: Watch the Agent Think

When you ask: **"What ports are open on 172.28.0.10?"**

The agent might:
```
Thought: I need to find open ports. I should use the quick scan tool.
Action: read_nmap_quick_scan
Action Input: {"target_ip": "172.28.0.10"}
Observation: [Quick scan results showing ports 80 and 3306]

Thought: I now have the information needed to answer the question.
Final Answer: The open ports are 80 (HTTP) and 3306 (MySQL).
```

## Available Tools (Agent Chooses!)

1. `read_nmap_quick_scan` - Fast port overview
2. `read_nmap_service_scan` - Detailed service versions
3. `read_osint_data` - Passive reconnaissance
4. `read_vulnerability_scan` - Security vulnerabilities
5. `read_port_summary` - High-level statistics

## Demo Questions

Each question demonstrates different agent behavior:

1. **"What ports are open?"** → Agent uses quick scan
2. **"What version of Apache?"** → Agent uses service scan
3. **"What technologies?"** → Agent combines OSINT + service scan
4. **"Any vulnerabilities?"** → Agent chains service → vulnerability scan
5. **"Complete analysis"** → Agent uses ALL tools

## Key Files

- `react_recon_agent.py` - Main agent implementation (150 lines)
- `react_recon_agent_generate_scan_logs.py` - Generate sample data
- `logs/*.json` - Sample log files the agent reads

## Learning Checkpoints

### After running, ask yourself:

- ✅ Why did the agent choose that tool first?
- ✅ How did it know to use multiple tools?
- ✅ What if you asked a different question?
- ✅ Can you predict which tools it will use?

## Advanced: Try These

1. Ask: "Compare quick scan vs service scan"
   - Watch the agent invoke BOTH tools

2. Ask: "Is Apache vulnerable?"
   - Watch it chain: service scan → vulnerability check

3. Create your own question!
   - The agent will figure out which tools to use

## The "Aha!" Moment

You'll know you understand ReAct when you can:
- Predict which tool the agent will use next
- Understand WHY it chose that tool
- See how each observation informs the next thought

This is **autonomous AI** in action! 🚀