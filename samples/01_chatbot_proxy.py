#!/usr/bin/env python3
"""
Sample 1: Customer Support Chatbot (Proxy Mode)

This simulates a real customer support chatbot where users might accidentally
share sensitive information. AIRS-CP intercepts and protects the data.

USAGE:
    # Start AIRS-CP gateway first
    uvicorn airs_cp.gateway.app:app --port 8080
    
    # Then run this chatbot
    python samples/01_chatbot_proxy.py

WHAT IT TESTS:
    - Zero-code integration (just change base_url)
    - PII detection and masking
    - Streaming responses
    - Session tracking via headers
"""

import os
import sys

# Check for OpenAI package
try:
    from openai import OpenAI
except ImportError:
    print("ERROR: Please install openai: pip install openai")
    sys.exit(1)


def get_client(use_airs: bool = True):
    """Get OpenAI client - with or without AIRS-CP."""
    if use_airs:
        # Through AIRS-CP (ONLY CHANGE = base_url)
        return OpenAI(
            base_url="http://localhost:8080/v1",
            api_key=os.getenv("OPENAI_API_KEY", "not-needed-for-ollama"),
        )
    else:
        # Direct to OpenAI (no security)
        return OpenAI()


def chat(client, messages: list, model: str = None, stream: bool = False):
    """Send chat request."""
    model = model or os.getenv("AIRS_MODEL", "llama3.2:1b")
    
    if stream:
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            stream=True,
        )
        full_response = ""
        for chunk in response:
            if chunk.choices[0].delta.content:
                content = chunk.choices[0].delta.content
                print(content, end="", flush=True)
                full_response += content
        print()
        return full_response
    else:
        response = client.chat.completions.create(
            model=model,
            messages=messages,
        )
        return response.choices[0].message.content


def main():
    print("=" * 60)
    print("  Customer Support Chatbot (Proxy Mode)")
    print("  Testing AIRS-CP PII Protection")
    print("=" * 60)
    
    client = get_client(use_airs=True)
    
    # System prompt
    system_message = {
        "role": "system",
        "content": "You are a helpful customer support agent for a bank. "
                   "Help customers with their account inquiries."
    }
    
    # Test scenarios
    test_scenarios = [
        # Normal query (should pass through)
        {
            "name": "Normal Query",
            "message": "What are your branch hours?",
            "expected": "Should respond normally",
        },
        # PII in message (should be masked)
        {
            "name": "SSN Leak",
            "message": "I need help with my account. My SSN is 123-45-6789",
            "expected": "SSN should be masked before reaching LLM",
        },
        # Credit card (should be masked)
        {
            "name": "Credit Card Leak",
            "message": "Please charge my card 4111-1111-1111-1111 for the fee",
            "expected": "Card number should be masked",
        },
        # Multiple PII types
        {
            "name": "Multiple PII",
            "message": "My email is john@example.com, phone is 555-123-4567, "
                      "and SSN is 987-65-4321",
            "expected": "All PII types should be detected and masked",
        },
        # Streaming with PII
        {
            "name": "Streaming Request",
            "message": "Tell me a short story about customer service",
            "expected": "Streaming should work with security scanning",
            "stream": True,
        },
    ]
    
    for i, scenario in enumerate(test_scenarios, 1):
        print(f"\n--- Test {i}: {scenario['name']} ---")
        print(f"Input: {scenario['message'][:60]}...")
        print(f"Expected: {scenario['expected']}")
        print()
        
        messages = [system_message, {"role": "user", "content": scenario["message"]}]
        
        try:
            stream = scenario.get("stream", False)
            print("Response: ", end="" if stream else "\n")
            response = chat(client, messages, stream=stream)
            if not stream:
                print(response[:200] + "..." if len(response) > 200 else response)
            print("\n✓ Request completed")
        except Exception as e:
            print(f"✗ Error: {e}")
        
        print("-" * 40)
    
    print("\n" + "=" * 60)
    print("  Tests Complete!")
    print("  Check AIRS-CP logs to verify PII was masked")
    print("=" * 60)


if __name__ == "__main__":
    main()
