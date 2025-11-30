"""
LangChain ReAct Agent - Educational Implementation
=================================================

LEARNING OBJECTIVE: Understanding how ReAct agents work
- How agents REASON about what to do
- How agents SELECT which tool to use
- How agents ACT by invoking tools
- How agents CHAIN multiple tools together

This is a proper ReAct (Reasoning + Acting) agent implementation.
Each tool reads from a specific log file type.
The agent decides which tools to invoke based on the user's question.
"""

import os
import json
from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_react_agent
from langchain.prompts import PromptTemplate
from langchain.tools import tool
from dotenv import load_dotenv
load_dotenv()
# ============================================================================
# SECTION 1: TOOL DEFINITIONS (Each tool reads a specific log file)
# ============================================================================

@tool
def read_nmap_quick_scan(target_ip: str) -> str:
    """
    Read results from a quick Nmap port scan.
    
    Use this when you need to quickly identify which ports are open on a system.
    This gives a fast overview without detailed version information.
    
    Args:
        target_ip: The IP address that was scanned
    
    Returns:
        Summary of open ports and services
    """
    log_file = "logs/nmap_quick_scan.json"
    try:
        with open(log_file, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return f"Log file not found: {log_file}"
    except Exception as e:
        return f"Failed to read {log_file}: {e}"
    
    result = f"Quick Scan Results for {target_ip}\n"
    result += "=" * 50 + "\n"
    result += f"Ports found: {len(data['open_ports'])}\n\n"
    
    for port in data['open_ports']:
        result += f"  • Port {port['port']}: {port['service']}\n"
    
    return result


@tool
def read_nmap_service_scan(target_ip: str) -> str:
    """
    Read results from a detailed Nmap service version detection scan.
    
    Use this when you need detailed information about service versions.
    This is slower but provides version numbers useful for vulnerability assessment.
    
    Args:
        target_ip: The IP address that was scanned
    
    Returns:
        Detailed service information with versions
    """
    log_file = "logs/nmap_service_scan.json"
    try:
        with open(log_file, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return f"Log file not found: {log_file}"
    except Exception as e:
        return f"Failed to read {log_file}: {e}"
    
    result = f"Service Detection Scan for {target_ip}\n"
    result += "=" * 50 + "\n\n"
    
    for port in data['open_ports']:
        result += f"Port {port['port']} ({port['service']})\n"
        result += f"  Version: {port.get('version', 'Unknown')}\n"
        result += f"  State: {port.get('state', 'open')}\n\n"
    
    if 'security_notes' in data:
        result += "Security Notes:\n"
        for note in data['security_notes']:
            result += f"  ⚠️  {note}\n"
    
    return result


@tool
def read_osint_data(target: str) -> str:
    """
    Read Open Source Intelligence (OSINT) data about a target.
    
    Use this for passive reconnaissance to gather publicly available information.
    Includes DNS records, HTTP headers, and technology identification.
    
    Args:
        target: Domain name or hostname to look up
    
    Returns:
        OSINT report with DNS, web server info, and technologies
    """
    log_file = "logs/osint_data.json"
    try:
        with open(log_file, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return f"Log file not found: {log_file}"
    except Exception as e:
        return f"Failed to read {log_file}: {e}"
    
    # Get target-specific data or default
    target_data = data.get(target.lower(), data.get('default', {}))
    
    result = f"OSINT Data for {target}\n"
    result += "=" * 50 + "\n\n"
    
    # DNS Records
    if 'dns_records' in target_data:
        result += "DNS Records:\n"
        dns = target_data['dns_records']
        result += f"  A: {', '.join(dns.get('A', ['None']))}\n"
        result += f"  MX: {', '.join(dns.get('MX', ['None']))}\n\n"
    
    # HTTP Info
    if 'http_info' in target_data:
        result += "Web Server Information:\n"
        http = target_data['http_info']
        for key, value in http.items():
            result += f"  {key}: {value}\n"
        result += "\n"
    
    # Technologies
    if 'technologies' in target_data:
        result += "Detected Technologies:\n"
        for tech, version in target_data['technologies'].items():
            result += f"  {tech}: {version}\n"
    
    return result


@tool
def read_vulnerability_scan(target_ip: str) -> str:
    """
    Read vulnerability assessment results.
    
    Use this to check if any known vulnerabilities were detected.
    This should typically be used after identifying services and versions.
    
    Args:
        target_ip: The IP address that was assessed
    
    Returns:
        List of identified vulnerabilities with severity ratings
    """
    log_file = "logs/vulnerability_scan.json"
    try:
        with open(log_file, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return f"Log file not found: {log_file}"
    except Exception as e:
        return f"Failed to read {log_file}: {e}"
    
    result = f"Vulnerability Assessment for {target_ip}\n"
    result += "=" * 50 + "\n\n"
    
    if 'vulnerabilities' in data:
        result += f"Total Vulnerabilities Found: {len(data['vulnerabilities'])}\n\n"
        
        for vuln in data['vulnerabilities']:
            result += f"[{vuln['severity']}] {vuln['title']}\n"
            result += f"  Service: {vuln['service']}\n"
            result += f"  Description: {vuln['description']}\n"
            result += f"  Recommendation: {vuln['recommendation']}\n\n"
    else:
        result += "No vulnerabilities data available.\n"
    
    return result


@tool
def read_port_summary(target_ip: str) -> str:
    """
    Read a high-level summary of all port scanning activities.
    
    Use this for a quick overview before diving into specific scan types.
    Shows what scans were performed and general statistics.
    
    Args:
        target_ip: The IP address that was scanned
    
    Returns:
        Summary of scanning activities and key statistics
    """
    log_file = "logs/port_summary.json"
    try:
        with open(log_file, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return f"Log file not found: {log_file}"
    except Exception as e:
        return f"Failed to read {log_file}: {e}"
    
    result = f"Port Scanning Summary for {target_ip}\n"
    result += "=" * 50 + "\n\n"
    
    result += f"Total Scans Performed: {data.get('total_scans', 0)}\n"
    result += f"Total Open Ports: {data.get('total_open_ports', 0)}\n"
    result += f"Total Services Identified: {data.get('total_services', 0)}\n\n"
    
    if 'notable_findings' in data:
        result += "Notable Findings:\n"
        for finding in data['notable_findings']:
            result += f"  • {finding}\n"
    
    return result


# ============================================================================
# SECTION 2: AGENT SETUP (The Heart of ReAct)
# ============================================================================

def create_react_agent_with_tools(api_key: str):
    """
    Create a LangChain ReAct agent with custom tools.
    
    This is the CORE of the learning exercise:
    - The agent will REASON about what information it needs
    - The agent will SELECT appropriate tools to gather that information
    - The agent will ACT by invoking those tools
    - The agent will iterate until it can answer the question
    
    Args:
        api_key: OpenAI API key
    
    Returns:
        Configured AgentExecutor
    """
    
    # Initialize the LLM that powers the agent's reasoning
    llm = ChatOpenAI(
        model_name="gpt-4o",
        temperature=0  # Deterministic for educational clarity
    )
    
    # Define ALL available tools the agent can choose from
    tools = [
        read_nmap_quick_scan,
        read_nmap_service_scan,
        read_osint_data,
        read_vulnerability_scan,
        read_port_summary
    ]
    
    # Create the ReAct prompt template
    # This is what makes it a "ReAct" agent (Reasoning + Acting)
    react_prompt = PromptTemplate.from_template("""
You are an AI agent that analyzes system reconnaissance data by reading log files.

You have access to these tools:
{tools}

Use the following format:

Question: the input question you must answer
Thought: you should always think about what to do
Action: the action to take, should be one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
... (this Thought/Action/Action Input/Observation can repeat N times)
Thought: I now know the final answer
Final Answer: the final answer to the original input question

IMPORTANT: 
- Think step by step about what information you need
- Choose the most appropriate tool for each piece of information
- You can use multiple tools to gather complete information
- Synthesize information from different tools into a coherent answer

Begin!

Question: {input}
Thought: {agent_scratchpad}
""")
    
    # Create the ReAct agent
    agent = create_react_agent(
        llm=llm,
        tools=tools,
        prompt=react_prompt
    )
    
    # Wrap in AgentExecutor which handles the execution loop
    agent_executor = AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=True,  # CRITICAL: Shows the ReAct reasoning process
        handle_parsing_errors=True,
        max_iterations=10,  # Prevent infinite loops
        return_intermediate_steps=True  # So we can see the reasoning chain
    )
    
    return agent_executor


# ============================================================================
# SECTION 3: DEMONSTRATION QUESTIONS
# ============================================================================

def get_demo_questions():
    """
    Predefined questions that demonstrate different ReAct patterns.
    
    Each question requires the agent to:
    1. Reason about what information is needed
    2. Select appropriate tools
    3. Potentially chain multiple tools together
    
    Returns:
        Dictionary of demo questions
    """
    return {
        "1": {
            "title": "Basic Port Discovery",
            "question": "What ports are open on 172.28.0.10?",
            "learning_focus": "Agent chooses between quick scan vs service scan"
        },
        "2": {
            "title": "Service Version Identification",
            "question": "What version of Apache is running on 172.28.0.10?",
            "learning_focus": "Agent must use service scan, not quick scan"
        },
        "3": {
            "title": "Technology Stack",
            "question": "What technologies and software are running on localhost?",
            "learning_focus": "Agent combines OSINT + service scan data"
        },
        "4": {
            "title": "Vulnerability Assessment",
            "question": "Are there any security vulnerabilities on 172.28.0.10?",
            "learning_focus": "Agent chains service detection → vulnerability scan"
        },
        "5": {
            "title": "Comprehensive Analysis",
            "question": "Give me a complete security analysis of 172.28.0.10 including technologies, open ports, and vulnerabilities.",
            "learning_focus": "Agent uses multiple tools: OSINT + quick scan + service scan + vuln scan"
        },
        "6": {
            "title": "Comparison Query",
            "question": "What's the difference between what a quick scan shows versus a service scan for 172.28.0.10?",
            "learning_focus": "Agent invokes BOTH scan types and compares"
        }
    }


# ============================================================================
# SECTION 4: MAIN PROGRAM
# ============================================================================

def main():
    """
    Main program demonstrating the ReAct agent.
    """
    
    print("\n" + "=" * 70)
    print("  LangChain ReAct Agent - Educational Demo")
    print("  Learning: How agents reason and select tools")
    print("=" * 70 + "\n")
    
    # Get API key from environment
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("❌ Error: OPENAI_API_KEY not found")
        print("Set it: export OPENAI_API_KEY='your-key-here'")
        return
    
    # Check log files exist
    if not os.path.exists("logs"):
        print("❌ Error: 'logs' directory not found")
        print("Create sample log files first")
        return
    
    print("✅ Environment ready\n")
    
    # Create the ReAct agent
    print("🤖 Creating ReAct agent with 5 tools...\n")
    agent = create_react_agent_with_tools(api_key)
    print("✅ Agent created\n")
    
    # Show available demo questions
    questions = get_demo_questions()
    
    print("📋 Demo Questions (each demonstrates different agent behavior):\n")
    for key, q in questions.items():
        print(f"{key}. {q['title']}")
        print(f"   Question: \"{q['question']}\"")
        print(f"   Learning: {q['learning_focus']}\n")
    
    print("0. Custom question")
    print("q. Quit\n")
    
    # Get user choice
    choice = input("👉 Select a question (0-6, or q): ").strip()
    
    if choice == 'q':
        print("\n👋 Goodbye!\n")
        return
    
    # Get the question
    if choice == '0':
        question = input("\n📝 Enter your question: ").strip()
        if not question:
            print("❌ No question provided")
            return
    elif choice in questions:
        question = questions[choice]['question']
        print(f"\n📋 Selected: {questions[choice]['title']}")
        print(f"🎯 Learning Focus: {questions[choice]['learning_focus']}")
    else:
        print("❌ Invalid choice")
        return
    
    # Run the agent
    print("\n" + "=" * 70)
    print("🤖 AGENT STARTING - Watch the ReAct Pattern")
    print("=" * 70)
    print(f"\nQuestion: {question}\n")
    print("=" * 70 + "\n")
    
    # Execute and observe the ReAct loop
    result = agent.invoke({"input": question})

    # Agent.invoke may return a string or a structured dict depending on LangChain version.
    # Normalize before printing.
    try:
        final_answer = result['output'] if isinstance(result, dict) and 'output' in result else result
    except Exception:
        final_answer = result

    # Show final answer
    print("\n" + "=" * 70)
    print("✅ FINAL ANSWER")
    print("=" * 70)
    print(final_answer)
    print("\n" + "=" * 70)
    
    # Educational summary
    print("\n📚 What just happened?")
    print("\nThe agent followed the ReAct pattern:")
    print("1. THOUGHT - Reasoned about what information it needed")
    print("2. ACTION - Selected which tool(s) to use")
    print("3. OBSERVATION - Read the tool results")
    print("4. Repeated steps 1-3 until it had enough information")
    print("5. Provided a FINAL ANSWER synthesizing all observations")
    
    print("\n🔍 Key Learning Points:")
    print("• The agent CHOSE which tools to use (you didn't tell it)")
    print("• The agent DECIDED the order of tool invocation")
    print("• The agent CHAINED tools together when needed")
    print("• Each 'Thought' shows the reasoning process")
    print("• This is autonomous decision-making in action!")
    
    print("\n💡 Try different questions to see different tool selection patterns!\n")


if __name__ == "__main__":
    main()