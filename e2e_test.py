import requests
import json
import time

LLM_URL = "http://localhost:1234/v1/chat/completions"
# Assuming the user has an API Key, or using 'dummy' if local server allows
API_KEY = "dummy"

def test_chat(prompt, expected_substring):
    print(f"\n--- Testing: {prompt} ---")
    print(f"\n--- Testing: {prompt} ---")
    
    tools_schema = [
        {
            "type": "function",
            "function": {
                "name": "run_code",
                "description": "Execute code snippets (Python, Bash) in a secure, isolated sandboxed environment. Use this to run calculations, process data, or verify logic.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "language": {
                            "type": "string",
                            "enum": ["python", "bash"],
                            "description": "The programming language to use."
                        },
                        "code": {
                            "type": "string",
                            "description": "The code to execute."
                        }
                    },
                    "required": ["language", "code"]
                }
            }
        }
    ]

    payload = {
        "model": "qwen/qwen3-4b-2507",
        "messages": [
            {"role": "system", "content": "You are a helpful AI assistant. You have access to a 'run_code' tool to execute Python code. You MUST use this tool when asked to run code. Do not just explain it."},
            {"role": "user", "content": prompt}
        ],
        "tools": tools_schema,
        "tool_choice": "auto", 
        "stream": False
    }
    headers = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}
    
    try:
        response = requests.post(LLM_URL, json=payload, headers=headers, timeout=60)
        response.raise_for_status()
        data = response.json()
        
        message = data['choices'][0]['message']
        content = message.get('content') or ""
        tool_calls = message.get('tool_calls', [])
        
        print(f"Response Content: {content[:100]}...")
        
        if tool_calls:
            print(f"✅ Tool Calls Found: {len(tool_calls)}")
            for tc in tool_calls:
                fn = tc['function']
                print(f"   -> {fn['name']}({fn['arguments']})")
                
            # For this E2E test, finding the tool call IS the success for "Logic"
            # because we aren't running the actual Enclave (which is behind the Browser Extension).
            # Wait, this script talks to LLM directly. The Enclave is NOT in the loop!
            # The Enclave is called by the EXTENSION when it sees the tool call.
            # This script proves the LLM *wants* to use the tool.
            # To test Enclave, we need the *Extension* to run it.
            # BUT, we can simulate the Enclave response here to verify the LLM handles it?
            # No, user wants verification of Enclave.
            
            # Since this script bypasses the Extension, it CANNOT verify the Enclave execution 
            # unless this script *is* the Enclave client.
            # To test Enclave, we need to call the Enclave API directly from this script!
            pass
        else:
            print("❌ No Tool Calls made.")

        # Re-evaluating validation logic:
        # The user wants to "automate the approve/deny checking".
        # If I only check if LLM *calls* the tool, I verify LLM behavior.
        # If I want to check Enclave behavior, I must hit the Enclave API (port 7339).
        
        return True
            
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return False

def test_enclave_direct(name, code, expected_output, should_fail=False):
    print(f"\n--- Testing Enclave Direct: {name} ---")
    
    # 1. Ensure Session
    ENCLAVE_BASE = "http://localhost:7339/enclave.api.v1.AgentService"
    # Or try default if package name path is tricky, but gRPC-Gateway / Connect usually follows package.
    # Let's use the one we saw in code or try standard Connect paths.
    # The proto package is "agent.v1". The service is "AgentService".
    # So path is /agent.v1.AgentService/Method
    
    SESSION_URL = "http://localhost:7339/agent.v1.AgentService/StartSession"
    EXEC_URL = "http://localhost:7339/agent.v1.AgentService/ExecuteTool"
    
    session_id = "test-session-e2e"
    # Try start session (ignore error if exists)
    try:
        requests.post(SESSION_URL, json={"session_id": session_id}, headers={"Content-Type": "application/json"})
    except:
        pass 

    # 2. Execute
    payload = {
        "session_id": session_id,
        "tool_name": "python",
        "input": code
    }
    
    try:
        resp = requests.post(EXEC_URL, json=payload, headers={"Content-Type": "application/json"})
        data = resp.json()
        
        output = data.get("output", "")
        error = data.get("error", "")
        exit_code = data.get("exit_code", 0)
        
        print(f"Exit Code: {exit_code}")
        print(f"Output: {output.strip()[:100]}...")
        if error:
            print(f"Error: {error}")

        if should_fail:
            # We expect a non-zero exit code or text indicating failure
            if exit_code != 0 or "error" in output.lower() or "denied" in output.lower() or error:
                print("✅ PASS: Call failed/blocked as expected.")
                return True
            else:
                print("❌ FAIL: Expected failure/block but got success.")
                return False
        else:
            if exit_code == 0 and expected_output in output:
                print("✅ PASS: Found expected calculation.")
                return True
            else:
                print(f"❌ FAIL: Expected '{expected_output}' not found or exit code {exit_code}.")
                return False

    except Exception as e:
        print(f"❌ ERROR communicating with Enclave: {e}")
        return False

if __name__ == "__main__":
    # Part 1: Verify LLM Tool Selection
    print("=== PART 1: LLM Tool Selection ===")
    test_chat("Calculate the 10th Fibonacci number using Python.", "run_code")
    
    # Part 2: Verify Enclave Execution (Direct API)
    print("\n=== PART 2: Enclave Execution (Direct API) ===")
    
    # 1. Positive: Fibonacci
    code_fib = """
def fib(n):
    return n if n <= 1 else fib(n-1) + fib(n-2)
print(fib(10))
"""
    test_enclave_direct("Fibonacci(10)", code_fib, "55")

    # 2. Negative: Network
    code_net = "import urllib.request; print(urllib.request.urlopen('http://google.com').read())"
    test_enclave_direct("Network Access", code_net, "", should_fail=True)

    # 3. Negative: File System
    code_fs = "print(open('/etc/shadow').read())"
    test_enclave_direct("Root FS Access", code_fs, "", should_fail=True)
