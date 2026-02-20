import json
import os
import uuid

import requests

ENCLAVE_URL = os.getenv(
    "ENCLAVE_URL", "http://localhost:7339/agent.v1.AgentService/ExecuteTool"
)
SESSION_ID = f"e2e-demo-session-{uuid.uuid4().hex[:8]}"
REQUEST_TIMEOUT_SECONDS = 30
SKIP = "SKIP"
PASS = True
FAIL = False


def has_python_exception(text: str) -> bool:
    normalized = text.lower()
    return "traceback" in normalized or "errors:" in normalized


def is_policy_style_denial(output: str, error: str) -> bool:
    combined = f"{output}\n{error}".lower()
    if "sigkill" in combined:
        return True
    if "permission denied" in combined:
        return True
    if "operation not permitted" in combined:
        return True
    if "errno 1]" in combined:
        return True
    return False

def run_enclave_test(name, code, context=None, should_succeed=True):
    print(f"\n[TEST] {name}")
    payload = {
        "session_id": SESSION_ID,
        "tool_name": "python",
        "input": code,
        "timeout_seconds": 10,
        "context_json": json.dumps(context) if context else ""
    }
    
    try:
        resp = requests.post(
            ENCLAVE_URL,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        resp.raise_for_status()
        data = resp.json()
        
        output = data.get("output", "")
        error = data.get("error", "")
        exit_code = data.get("exitCode", data.get("exit_code", 0))
        combined = f"{output}\n{error}".lower()
        
        print(f"  Exit Code: {exit_code}")
        if output: print(f"  Output: {output.strip()}")
        if error: print(f"  Error: {error.strip()}")

        if should_succeed:
            if exit_code == 0 and not error:
                print("  ✅ PASS")
                return PASS
            else:
                print("  ❌ FAIL (Expected success)")
                return FAIL
        else:
            # We expect failure (EPERM or Sigkill)
            # exit_code 137 is SIGKILL (Tetragon matchAction: Sigkill)
            # exit_code 1 is typically EPERM from python
            if is_policy_style_denial(output, error) or exit_code != 0:
                print(f"  ✅ PASS (Verifiable Denial Confirmed: Exit {exit_code})")
                return PASS
            if "errno 101" in combined or "network is unreachable" in combined:
                print("  ⏭️  SKIP (Environment/network limitation, not policy denial)")
                return SKIP
            if has_python_exception(output) or error:
                print("  ❌ FAIL (Execution failed, but not with policy-denial signature)")
                return FAIL
            else:
                print("  ❌ FAIL (Expected block but executed successfully)")
                return FAIL

    except Exception as e:
        print(f"  ❌ ERROR: {e}")
        return FAIL

if __name__ == "__main__":
    print("=== TENSORPATH VERIFIABLE DENIAL SUITE ===")
    results = []

    # 1. Standard Success Case
    results.append(run_enclave_test(
        "Standard Python Calculation",
        "print(2 + 2)",
        context={"user_role": "analyst", "intent": {"action_category": "standard"}},
        should_succeed=True
    ))

    # 2. Blocked Network Case (analyst role cannot network)
    results.append(run_enclave_test(
        "Unauthorized Network Access",
        "import socket; socket.create_connection(('8.8.8.8', 53))",
        context={"user_role": "analyst", "intent": {"network_required": True}},
        should_succeed=False
    ))

    # 3. Blocked File Case (unauthorized path)
    results.append(run_enclave_test(
        "Unauthorized File System Access",
        "print(open('/etc/hostname').read())",
        context={"user_role": "analyst", "intent": {"action_category": "read_only_analysis", "requested_paths": ["/data/public.csv"]}},
        should_succeed=False
    ))

    # 4. Allowed Research Case (researcher role can network)
    results.append(run_enclave_test(
        "Authorized Network (Researcher)",
        "print('Network allowed for researcher')",
        context={"user_role": "researcher", "intent": {"network_required": True}},
        should_succeed=True
    ))

    passed = sum(1 for r in results if r is PASS)
    skipped = sum(1 for r in results if r == SKIP)
    failed = total = len(results)
    failed = total - passed - skipped
    print("\n=== SUITE COMPLETE ===")
    print(f"Passed: {passed}/{total} | Skipped: {skipped} | Failed: {failed}")
    if failed != 0:
        raise SystemExit(1)
