#!/usr/bin/env python3
"""
AIRS-CP Gateway Demo Script

This script demonstrates the gateway functionality without requiring
a full agentic AI application. It tests:
1. Health check
2. Non-streaming chat completion
3. Streaming chat completion
4. Control endpoints (mode, kill switch)

Usage:
    # Start gateway first:
    uvicorn airs_cp.gateway.app:app --port 8080
    
    # Then run this script:
    python scripts/demo.py
    
    # Or with custom gateway URL:
    python scripts/demo.py --gateway http://localhost:8080
"""

import argparse
import sys
import time

# Check for required packages
try:
    import httpx
except ImportError:
    print("Installing httpx...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "httpx", "-q"])
    import httpx

try:
    from openai import OpenAI
except ImportError:
    print("Installing openai...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "openai", "-q"])
    from openai import OpenAI


def print_header(title: str):
    """Print a section header."""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def test_health(gateway_url: str) -> bool:
    """Test health endpoint."""
    print_header("1. Health Check")
    
    try:
        response = httpx.get(f"{gateway_url}/health", timeout=10)
        data = response.json()
        
        print(f"Status: {data['status']}")
        print(f"Mode: {data['mode']}")
        print(f"Provider: {data['provider']}")
        print(f"Kill Switch: {data['kill_switch']}")
        print(f"Version: {data['version']}")
        
        if data['status'] == 'healthy':
            print("\n✅ Health check PASSED")
            return True
        else:
            print("\n❌ Health check FAILED")
            return False
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def test_status(gateway_url: str) -> bool:
    """Test status endpoint."""
    print_header("2. Status Check")
    
    try:
        response = httpx.get(f"{gateway_url}/status", timeout=10)
        data = response.json()
        
        print(f"Status: {data['status']}")
        print(f"Uptime: {data['uptime_seconds']:.1f} seconds")
        print(f"Adapters: {data['adapters']}")
        
        print("\n✅ Status check PASSED")
        return True
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def test_models(gateway_url: str) -> bool:
    """Test models endpoint."""
    print_header("3. List Models")
    
    try:
        response = httpx.get(f"{gateway_url}/v1/models", timeout=30)
        data = response.json()
        
        if data.get('data'):
            print("Available models:")
            for model in data['data'][:5]:  # Show first 5
                print(f"  - {model['id']}")
            if len(data['data']) > 5:
                print(f"  ... and {len(data['data']) - 5} more")
            print("\n✅ Models list PASSED")
            return True
        else:
            print("No models found (is Ollama running?)")
            return False
            
    except Exception as e:
        print(f"❌ Error: {e}")
        print("Note: This may fail if Ollama isn't running")
        return False


def test_chat_completion(gateway_url: str, model: str) -> bool:
    """Test non-streaming chat completion."""
    print_header("4. Chat Completion (Non-Streaming)")
    
    try:
        # Use OpenAI SDK pointing to our gateway
        client = OpenAI(
            base_url=f"{gateway_url}/v1",
            api_key="not-needed-for-ollama"
        )
        
        print(f"Sending request to model: {model}")
        print("Prompt: 'Say hello in exactly 5 words.'")
        print()
        
        start = time.time()
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "user", "content": "Say hello in exactly 5 words."}
            ],
            max_tokens=50,
        )
        elapsed = time.time() - start
        
        content = response.choices[0].message.content
        print(f"Response: {content}")
        print(f"Time: {elapsed:.2f}s")
        print(f"Tokens: {response.usage.total_tokens if response.usage else 'N/A'}")
        
        print("\n✅ Chat completion PASSED")
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def test_streaming(gateway_url: str, model: str) -> bool:
    """Test streaming chat completion."""
    print_header("5. Chat Completion (Streaming)")
    
    try:
        client = OpenAI(
            base_url=f"{gateway_url}/v1",
            api_key="not-needed-for-ollama"
        )
        
        print(f"Sending streaming request to model: {model}")
        print("Prompt: 'Count from 1 to 5, one number per line.'")
        print()
        print("Streaming response:")
        print("-" * 40)
        
        start = time.time()
        stream = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "user", "content": "Count from 1 to 5, one number per line."}
            ],
            max_tokens=100,
            stream=True,
        )
        
        full_response = ""
        for chunk in stream:
            if chunk.choices[0].delta.content:
                content = chunk.choices[0].delta.content
                print(content, end="", flush=True)
                full_response += content
        
        elapsed = time.time() - start
        print()
        print("-" * 40)
        print(f"Time: {elapsed:.2f}s")
        
        print("\n✅ Streaming PASSED")
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def test_control_endpoints(gateway_url: str) -> bool:
    """Test control endpoints."""
    print_header("6. Control Endpoints")
    
    try:
        # Test mode change
        print("Testing mode change to 'enforce'...")
        response = httpx.post(
            f"{gateway_url}/mode",
            json={"mode": "enforce"},
            timeout=10
        )
        print(f"  Response: {response.json()}")
        
        # Change back to observe
        print("Changing back to 'observe'...")
        response = httpx.post(
            f"{gateway_url}/mode",
            json={"mode": "observe"},
            timeout=10
        )
        print(f"  Response: {response.json()}")
        
        # Test kill switch
        print("\nTesting kill switch activation...")
        response = httpx.post(f"{gateway_url}/kill", timeout=10)
        print(f"  Response: {response.json()}")
        
        # Verify via health
        health = httpx.get(f"{gateway_url}/health", timeout=10).json()
        print(f"  Kill switch active: {health['kill_switch']}")
        
        # Deactivate
        print("Deactivating kill switch...")
        response = httpx.delete(f"{gateway_url}/kill", timeout=10)
        print(f"  Response: {response.json()}")
        
        print("\n✅ Control endpoints PASSED")
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def test_metrics(gateway_url: str) -> bool:
    """Test Prometheus metrics endpoint."""
    print_header("7. Prometheus Metrics")
    
    try:
        response = httpx.get(f"{gateway_url}/metrics", timeout=10)
        
        print("Metrics (Prometheus format):")
        print("-" * 40)
        for line in response.text.split("\n")[:10]:
            print(f"  {line}")
        print("-" * 40)
        
        print("\n✅ Metrics PASSED")
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="AIRS-CP Gateway Demo")
    parser.add_argument(
        "--gateway",
        default="http://localhost:8080",
        help="Gateway URL (default: http://localhost:8080)"
    )
    parser.add_argument(
        "--model",
        default="llama3.2:1b",
        help="Model to use for chat tests (default: llama3.2:1b)"
    )
    parser.add_argument(
        "--skip-chat",
        action="store_true",
        help="Skip chat completion tests (if Ollama not available)"
    )
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print("  AIRS-CP Gateway Demo")
    print("="*60)
    print(f"\nGateway URL: {args.gateway}")
    print(f"Model: {args.model}")
    
    results = []
    
    # Run tests
    results.append(("Health Check", test_health(args.gateway)))
    results.append(("Status Check", test_status(args.gateway)))
    results.append(("List Models", test_models(args.gateway)))
    
    if not args.skip_chat:
        results.append(("Chat Completion", test_chat_completion(args.gateway, args.model)))
        results.append(("Streaming", test_streaming(args.gateway, args.model)))
    
    results.append(("Control Endpoints", test_control_endpoints(args.gateway)))
    results.append(("Metrics", test_metrics(args.gateway)))
    
    # Summary
    print_header("Summary")
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {name}: {status}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! Gateway is working correctly.")
        return 0
    else:
        print("\n⚠️  Some tests failed. Check the output above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
