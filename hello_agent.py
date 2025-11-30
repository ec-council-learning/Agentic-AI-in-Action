"""
Hello, Agent - Test Script
Verifies LLM connection and basic LangChain functionality
"""

import os
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain.schema import HumanMessage, SystemMessage

def main():
    # Load environment variables from .env file
    load_dotenv()
    
    # Verify API key is loaded
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY not found in environment variables!")
    
    print("🔐 API Key loaded successfully!")
    print(f"🔑 Key prefix: {api_key[:7]}...")
    
    # Initialize the LLM
    print("\n🤖 Initializing AI Agent...")
    llm = ChatOpenAI(
        model="gpt-4o-mini",  # Cost-effective model for development
        temperature=0.7,
        api_key=api_key
    )
    
    # Create messages
    messages = [
        SystemMessage(content="You are a helpful AI agent specializing in cybersecurity. You provide clear, concise, and secure guidance."),
        HumanMessage(content="Hello! Please introduce yourself and confirm you're ready to assist with cybersecurity tasks.")
    ]
    
    # Get response from the agent
    print("\n📡 Sending request to AI Agent...")
    response = llm.invoke(messages)
    
    # Display the response
    print("\n" + "="*60)
    print("🎯 AGENT RESPONSE:")
    print("="*60)
    print(response.content)
    print("="*60)
    
    # Additional verification
    print("\n✅ Connection successful!")
    print(f"📊 Model used: {llm.model_name}")
    print(f"🌡️  Temperature: {llm.temperature}")
    print("\n🎉 Your development environment is ready!")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("\n🔧 Troubleshooting tips:")
        print("  1. Verify your .env file exists and contains OPENAI_API_KEY")
        print("  2. Check your API key is valid at https://platform.openai.com/api-keys")
        print("  3. Ensure you have internet connectivity")
        print("  4. Verify your OpenAI account has available credits")
