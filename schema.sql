-- TensorPath Reactor Schema
-- Defined in docs/enclave-db.md

CREATE TABLE IF NOT EXISTS enclave_events (
    id BIGSERIAL PRIMARY KEY,
    session_id UUID NOT NULL,
    timestamp BIGINT NOT NULL,          -- Nanoseconds since epoch
    
    -- Event Classification
    action TEXT NOT NULL,               -- e.g., SYSCALL:OPENAT, EXECUTE:PYTHON
    status TEXT NOT NULL,               -- ALLOWED, BLOCKED, ERROR
    
    -- Payload
    input TEXT,                         -- Arguments (truncated if massive)
    metadata JSONB,                     -- PID, ToolName, ReturnCode, Latency
    
    -- Indexing for Dashboard
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Optimize for time-series queries (Dashboard)
CREATE INDEX IF NOT EXISTS idx_enclave_events_session_ts ON enclave_events(session_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_enclave_events_ts ON enclave_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_enclave_events_action ON enclave_events(action);
