#!/usr/bin/env python3
"""
Example: Simple Chatbot through AIRS-CP Gateway

This demonstrates how ANY application can integrate with AIRS-CP
using the standard OpenAI SDK - zero code changes required except
changing the base_url.

This is "proxy mode" integration - the simplest way to add
security to your LLM applications.

Usage:
    # Start gateway first:
    uvicorn airs_cp.gateway.app:app --port 8080
    
    # Start Ollama (if not running):
    ollama serve
    
    # Run chatbot:
    python examples/simple_chatbot.py
"""

import sys

try:
    from openai import OpenAI
except ImportError:
    print("Installing openai package...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "openai", "-q"])
    from openai import OpenAI


def main():
    # ==========================================================
    # THIS IS THE ONLY CHANGE NEEDED FOR AIRS-CP INTEGRATION!
    # Instead of: client = OpenAI()
    # Use: client = OpenAI(base_url="http://localhost:8080/v1", ...)
    # ==========================================================
    
    GATEWAY_URL = "http://localhost:8080/v1"
    MODEL = "llama3.2:1b"  # Change to your model
    
    client = OpenAI(
        base_url=GATEWAY_URL,
        api_key="not-needed-for-ollama"  # Only needed for cloud providers
    )
    
    print("=" * 60)
    print("  Simple Chatbot (via AIRS-CP Gateway)")
    print("=" * 60)
    print(f"\nGateway: {GATEWAY_URL}")
    print(f"Model: {MODEL}")
    print("\nType 'quit' to exit, 'stream' to toggle streaming")
    print("-" * 60)
    
    conversation = []
    streaming = True
    
    while True:
        try:
            user_input = input("\nYou: ").strip()
            
            if not user_input:
                continue
            
            if user_input.lower() == 'quit':
                print("Goodbye!")
                break
            
            if user_input.lower() == 'stream':
                streaming = not streaming
                print(f"Streaming: {'ON' if streaming else 'OFF'}")
                continue
            
            if user_input.lower() == 'clear':
                conversation = []
                print("Conversation cleared.")
                continue
            
            # Add user message to conversation
            conversation.append({"role": "user", "content": user_input})
            
            print("\nAssistant: ", end="", flush=True)
            
            if streaming:
                # Streaming response
                stream = client.chat.completions.create(
                    model=MODEL,
                    messages=conversation,
                    max_tokens=500,
                    stream=True,
                )
                
                full_response = ""
                for chunk in stream:
                    if chunk.choices[0].delta.content:
                        content = chunk.choices[0].delta.content
                        print(content, end="", flush=True)
                        full_response += content
                print()  # Newline after response
                
            else:
                # Non-streaming response
                response = client.chat.completions.create(
                    model=MODEL,
                    messages=conversation,
                    max_tokens=500,
                )
                full_response = response.choices[0].message.content
                print(full_response)
            
            # Add assistant response to conversation
            conversation.append({"role": "assistant", "content": full_response})
            
        except KeyboardInterrupt:
            print("\n\nGoodbye!")
            break
        except Exception as e:
            print(f"\nError: {e}")
            print("Make sure the gateway and Ollama are running.")


if __name__ == "__main__":
    main()
