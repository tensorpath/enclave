import json
import os

import requests

ENCLAVE_URL = os.getenv(
    "ENCLAVE_URL", "http://localhost:7339/agent.v1.AgentService/ExecuteTool"
)

def check_tetra():
    payload = {
        "session_id": "00000000-0000-0000-0000-000000000001",
        "tool_name": "bash",
        "input": "/usr/local/bin/tetra tracingpolicy list",
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
    check_tetra()
