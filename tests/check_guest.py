import json
import os

import requests

ENCLAVE_URL = os.getenv(
    "ENCLAVE_URL", "http://localhost:7339/agent.v1.AgentService/ExecuteTool"
)

def check_guest():
    payload = {
        "session_id": "00000000-0000-0000-0000-000000000001",
        "tool_name": "python",
        "input": "import subprocess; h = subprocess.check_output(['/usr/local/bin/tetragon', '--help']).decode(); print('\\n'.join([l for l in h.splitlines() if 'tracing-policy' in l or 'config' in l]))",
        "context_json": json.dumps({"user_role": "admin"})
    }
    resp = requests.post(
        ENCLAVE_URL,
        json=payload,
        headers={"Content-Type": "application/json"},
        timeout=30,
    )
    resp.raise_for_status()
    print(resp.json())

if __name__ == "__main__":
    check_guest()
