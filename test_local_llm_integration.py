#!/usr/bin/env python3
"""
Test script to verify local LLM integration with Vajra AI
Tests the flow: Browser → Flask → AI Engine → Local LLM (localhost:8080)
"""

import sys
import json
import urllib.request
import urllib.error

def test_local_llm_direct():
    """Test direct connection to local LLM"""
    print("=" * 70)
    print("STEP 1: Direct Test of Local LLM at localhost:8080")
    print("=" * 70)
    
    url = "http://localhost:8080/v1/chat/completions"
    payload = {
        "model": "default",
        "messages": [
            {"role": "user", "content": "What is CVE-2024-1234? Explain its MITRE ATT&CK mapping."}
        ],
        "max_tokens": 200,
        "stream": False,
        "temperature": 0.7
    }
    
    try:
        print(f"Sending CVE query to {url}...")
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))
            if data.get("choices"):
                response_text = data["choices"][0].get("message", {}).get("content", "")
                print(f"\n✅ LOCAL LLM RESPONDING!")
                print(f"Response preview: {response_text[:200]}...\n")
                return True
    except Exception as e:
        print(f"❌ Direct test failed: {type(e).__name__}: {str(e)}\n")
        return False


def test_vajra_ai_integration():
    """Test Vajra AI integration with local API"""
    print("=" * 70)
    print("STEP 2: Test Vajra AI Integration")
    print("=" * 70)
    
    from ai_engine import VajraAI
    from conversation_store import ConversationStore
    
    # Initialize
    ai_engine = VajraAI()
    conversation_store = ConversationStore()
    
    # Configure for local LLM
    print("Configuring Vajra AI for local LLM...")
    ai_engine.set_local_api_config("http://localhost:8080", "default")
    ai_engine.set_active_model("local-api")
    
    config = ai_engine.get_local_api_config()
    print(f"Local API Config: {config}")
    print(f"Active Model: {ai_engine.get_active_model()}")
    
    # Test connection
    print("\nTesting local API connection...")
    test_result = ai_engine.test_local_api_connection()
    print(f"Test Result: {test_result}")
    
    if not test_result.get("success"):
        print(f"❌ Connection test failed: {test_result.get('error')}")
        return False
    
    print("✅ Connection test passed!")
    
    # Test actual query
    print("\nSending test query through Vajra AI...")
    message = "What is MITRE ATT&CK framework? Explain in one sentence."
    
    try:
        print(f"Query: {message}")
        response = ai_engine.generate_response(message, [])
        print(f"\n✅ Got response from local LLM via Vajra AI!")
        print(f"Response: {response[:300]}...\n")
        return True
    except Exception as e:
        print(f"❌ Query failed: {type(e).__name__}: {str(e)}\n")
        return False


def test_flask_endpoint():
    """Test Flask endpoint"""
    print("=" * 70)
    print("STEP 3: Test Flask REST Endpoint")
    print("=" * 70)
    
    print("Starting Flask app test...\n")
    
    try:
        from app import app, ai_engine
        
        # Configure AI engine for local LLM
        ai_engine.set_local_api_config("http://localhost:8080", "default")
        ai_engine.set_active_model("local-api")
        
        # Create a test client
        client = app.test_client()
        
        # Test settings endpoint
        print("1. Testing GET /api/settings/local-api...")
        response = client.get("/api/settings/local-api")
        if response.status_code == 200:
            config = response.get_json()
            print(f"   ✅ Config: {config}\n")
        else:
            print(f"   ❌ Failed: {response.status_code}\n")
            return False
        
        # Test connection
        print("2. Testing POST /api/settings/local-api/test...")
        response = client.post("/api/settings/local-api/test")
        test_result = response.get_json()
        if test_result.get("success"):
            print(f"   ✅ Connection successful!\n")
        else:
            print(f"   ❌ Test failed: {test_result.get('error')}\n")
            return False
        
        # Test chat endpoint
        print("3. Testing POST /api/chat (non-streaming)...")
        response = client.post(
            "/api/chat",
            json={
                "message": "Explain CVE and MITRE ATT&CK in one sentence"
            }
        )
        
        if response.status_code == 200:
            data = response.get_json()
            print(f"   ✅ Conversation ID: {data.get('conversation_id')}")
            print(f"   Response preview: {str(data.get('response', ''))[:150]}...\n")
            return True
        else:
            print(f"   ❌ Failed: {response.status_code}\n")
            print(f"   Response: {response.get_json()}\n")
            return False
            
    except Exception as e:
        print(f"❌ Flask test failed: {type(e).__name__}: {str(e)}\n")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests"""
    print("\n")
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 68 + "║")
    print("║" + "   VAJRA AI ↔ LOCAL LLM INTEGRATION TEST".center(68) + "║")
    print("║" + "   Testing: Browser → Flask → AI Engine → Local LLM".center(68) + "║")
    print("║" + " " * 68 + "║")
    print("╚" + "=" * 68 + "╝")
    print()
    
    results = {
        "Direct LLM": test_local_llm_direct(),
        "Vajra AI": test_vajra_ai_integration(),
        "Flask Endpoint": test_flask_endpoint(),
    }
    
    # Summary
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    for test_name, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{test_name:<30} {status}")
    
    all_passed = all(results.values())
    print()
    
    if all_passed:
        print("🎉 ALL TESTS PASSED!")
        print("\nVajra AI is now configured to send queries to your local LLM:")
        print("  1. Open http://localhost:5000 in your browser")
        print("  2. Go to Settings → Local API")
        print("  3. Verify URL is: http://localhost:8080")
        print("  4. Verify Model is: default")
        print("  5. Select 'Local API' from the model dropdown")
        print("  6. Send a security query (CVE, MITRE ATT&CK, etc.)")
        print("\n✨ Your local LLM will power Vajra AI responses!")
        return 0
    else:
        print("⚠️  Some tests failed. Check the output above for details.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
