#!/usr/bin/env python3
"""
Example: SDK Mode Integration

This demonstrates SDK mode integration which provides additional
features beyond proxy mode:
- Session tracking for audit trail
- Tags for request categorization
- Direct access to control endpoints

Usage:
    # Start gateway first:
    uvicorn airs_cp.gateway.app:app --port 8080
    
    # Run example:
    python examples/sdk_integration.py
"""

import sys
import os
from typing import cast, Iterator

# Add src to path for local development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from airs_cp.sdk.client import AIRSClient, ChatCompletion, StreamChunk


def main():
    print("=" * 60)
    print("  AIRS-CP SDK Integration Example")
    print("=" * 60)
    
    # Initialize client with session tracking
    # Note: use airs_endpoint (not base_url) and default_session_id (not session_id)
    client = AIRSClient(
        airs_endpoint="http://localhost:8080",
        default_session_id="user-session-12345",  # Track this user's session
    )
    
    # 1. Check gateway health
    print("\n1. Checking gateway health...")
    health = client.health()
    print(f"   Status: {health['status']}")
    print(f"   Mode: {health['mode']}")
    print(f"   Provider: {health['provider']}")
    
    # 2. Get detailed status
    print("\n2. Getting detailed status...")
    status = client.status()
    print(f"   Uptime: {status['uptime_seconds']:.1f}s")
    
    # 3. Chat completion with tags
    print("\n3. Chat completion with tags...")
    # Use cast() for type safety since create() returns Union type
    response = cast(ChatCompletion, client.chat.completions.create(
        model="llama3.2:1b",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "What is the capital of France?"}
        ],
        tags=["geography", "factual"],  # Tags for categorization
    ))
    # Check for None content
    content = response.choices[0].message.content if response.choices[0].message.content else "(empty)"
    print(f"   Response: {content}")
    
    # 4. Streaming with session tracking
    print("\n4. Streaming response...")
    print("   Response: ", end="")
    
    # Use cast() for streaming - create() returns Iterator[StreamChunk] when stream=True
    stream = cast(Iterator[StreamChunk], client.chat.completions.create(
        model="llama3.2:1b",
        messages=[
            {"role": "user", "content": "Count from 1 to 3."}
        ],
        stream=True,
    ))
    
    for chunk in stream:
        # StreamChunk uses delta_content directly, not choices[0].delta.content
        if chunk.delta_content:
            print(chunk.delta_content, end="", flush=True)
    print()
    
    # 5. Test control endpoints
    print("\n5. Testing control endpoints...")
    
    # Get current mode
    print(f"   Current mode: {health['mode']}")
    
    # Change to enforce mode
    result = client.set_mode("enforce")
    print(f"   Changed to: {result['mode']}")
    
    # Change back to observe
    result = client.set_mode("observe")
    print(f"   Changed back to: {result['mode']}")
    
    # 6. Test kill switch (carefully!)
    print("\n6. Testing kill switch...")
    
    # Activate
    result = client.kill(activate=True)
    print(f"   Kill switch activated: {result}")
    
    # Verify
    health = client.health()
    print(f"   Effective mode: {health['mode']} (kill switch forces observe)")
    
    # Deactivate
    result = client.kill(activate=False)
    print(f"   Kill switch deactivated: {result}")
    
    print("\n" + "=" * 60)
    print("  All SDK features demonstrated successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
