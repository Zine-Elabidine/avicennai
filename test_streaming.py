#!/usr/bin/env python3
"""
Test streaming functionality for both conversation and rule generation
"""
import asyncio
import sys
import os

# Add the app directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from app.engine.agents.avicennai_agent import DetectionAndResponseEngineerAgent

async def test_conversation_streaming():
    """Test streaming for conversational responses"""
    
    print(" Testing Conversational Streaming")
    print("=" * 50)
    
    # Initialize agent
    agent = DetectionAndResponseEngineerAgent()
    
    conversation_prompts = [
        "Hello! How are you today?",
        "What is threat hunting and how does it work?",
        "Can you explain the difference between SIEM and SOAR?"
    ]
    
    for i, prompt in enumerate(conversation_prompts, 1):
        print(f"\n{i}. User: {prompt}")
        print("Agent: ", end="", flush=True)
        
        try:
            # Stream the response
            async for chunk in agent.stream(prompt):
                print(chunk, end="", flush=True)
            print()  # New line after streaming
            
        except Exception as e:
            print(f"\n Streaming error: {str(e)}")
    
    print(f"\n Final chat history length: {len(agent.chat_history)}")

async def test_rule_generation_streaming():
    """Test streaming for rule generation"""
    
    print("\n Testing Rule Generation Streaming")
    print("=" * 50)
    
    # Initialize agent
    agent = DetectionAndResponseEngineerAgent()
    
    rule_prompt = "Generate a detection rule for suspicious file downloads"
    
    print(f"User: {rule_prompt}")
    print("Agent: ", end="", flush=True)
    
    try:
        # Stream rule generation without timeout
        async for chunk in agent.stream(rule_prompt):
            print(chunk, end="", flush=True)
        print()  # New line after streaming
        print(" Rule generation streaming completed!")
        
    except Exception as e:
        print(f"\n Streaming error: {str(e)}")
    
    print(f"\n Final chat history length: {len(agent.chat_history)}")

async def test_mixed_streaming():
    """Test mixed conversation and rule generation streaming"""
    
    print("\n Testing Mixed Streaming (Conversation + Rule Generation)")
    print("=" * 60)
    
    # Initialize agent
    agent = DetectionAndResponseEngineerAgent()
    
    mixed_prompts = [
        "Hi! I need help with cybersecurity.",
        "Create a rule for detecting credential dumping",
        "Thanks! Can you explain what we just created?"
    ]
    
    for i, prompt in enumerate(mixed_prompts, 1):
        print(f"\n{i}. User: {prompt}")
        print("Agent: ", end="", flush=True)
        
        try:
            # Stream without timeout
            async for chunk in agent.stream(prompt):
                print(chunk, end="", flush=True)
            print()  # New line after streaming
            
        except Exception as e:
            print(f"\n Streaming error: {str(e)}")
    
    print(f"\n Final chat history length: {len(agent.chat_history)}")

if __name__ == "__main__":
    # Test conversation streaming (quick)
    #asyncio.run(test_conversation_streaming())
    
    # Test rule generation streaming (longer)
    #asyncio.run(test_rule_generation_streaming())
    
    # Test mixed streaming
    asyncio.run(test_mixed_streaming()) 