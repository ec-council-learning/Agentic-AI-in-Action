"""
LangSmith Tracing Test
Demonstrates observability for AI agent interactions
"""

import os
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain.schema import HumanMessage, SystemMessage

def test_langsmith_tracing():
    # Load environment variables
    load_dotenv()
    
    # Verify LangSmith is configured
    if not os.getenv("LANGCHAIN_API_KEY"):
        print("⚠️  Warning: LANGCHAIN_API_KEY not set. Tracing will be disabled.")
    else:
        print("✅ LangSmith tracing enabled!")
        print(f"📊 Project: {os.getenv('LANGCHAIN_PROJECT')}")
    
    # Initialize LLM
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    
    # Test query - simulating a cybersecurity use case
    messages = [
        SystemMessage(content="You are a cybersecurity AI agent."),
        HumanMessage(content="What are the top 3 OWASP Top 10 vulnerabilities I should prioritize for a web application?")
    ]
    
    print("\n🔍 Running traced query...")
    response = llm.invoke(messages)
    
    print("\n📝 Response received:")
    print(response.content[:200] + "...")
    
    print("\n🎯 Check your LangSmith dashboard to see the trace!")
    print("   URL: https://smith.langchain.com/")

if __name__ == "__main__":
    test_langsmith_tracing()
