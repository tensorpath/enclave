import json
import os
import uuid

import requests


ENCLAVE_URL = os.getenv(
    "ENCLAVE_URL", "http://localhost:7339/agent.v1.AgentService/ExecuteTool"
)
REQUEST_TIMEOUT_SECONDS = 30


def execute(payload: dict) -> dict:
    response = requests.post(
        ENCLAVE_URL,
        json=payload,
        headers={"Content-Type": "application/json"},
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    return response.json()


def read_exit_code(data: dict) -> int:
    if "exitCode" in data:
        return int(data["exitCode"])
    return int(data.get("exit_code", 0))


def test_violation():
    payload = {
        "session_id": f"test-jit-violation-{uuid.uuid4().hex[:8]}",
        "tool_name": "bash",
        "input": "cat /etc/hostname",
        "timeout_seconds": 10,
        "context_json": json.dumps({"user_role": "analyst"}),
    }

    data = execute(payload)
    output = data.get("output", "")
    error = data.get("error", "")
    exit_code = read_exit_code(data)

    # Blocked behavior can surface as non-zero exit, policy error text, or explicit denial hints.
    blocked = (
        exit_code != 0
        or "permission denied" in output.lower()
        or "permission denied" in error.lower()
        or "sigkill" in error.lower()
        or "denied" in error.lower()
    )

    assert blocked, (
        "Expected analyst command to be blocked, but it appears allowed. "
        f"exit_code={exit_code}, output={output!r}, error={error!r}, raw={data!r}"
    )


if __name__ == "__main__":
    test_violation()
    print("PASS: policy violation test was blocked as expected")
