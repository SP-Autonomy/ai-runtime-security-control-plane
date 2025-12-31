# Data Model

## Overview

AIRS-CP uses SQLite by default with optional PostgreSQL support for production deployments.

## Core Tables

### sessions

Tracks unique interaction sessions.

```sql
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,           -- ISO 8601
    updated_at TEXT NOT NULL,           -- ISO 8601
    user_id TEXT,                       -- Optional user identifier
    tags TEXT,                          -- JSON array of tags
    metadata TEXT,                      -- JSON object
    status TEXT DEFAULT 'active'        -- active|closed|quarantined
);
```

### events

Captures all security-relevant events.

```sql
CREATE TABLE events (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,            -- ISO 8601
    event_type TEXT NOT NULL,           -- request|response|detection|action
    direction TEXT,                     -- inbound|outbound
    content TEXT,                       -- Redacted content
    content_hash TEXT,                  -- SHA-256 of original
    provider TEXT,                      -- openai|anthropic|azure|ollama
    model TEXT,                         -- Model used
    tokens_in INTEGER,
    tokens_out INTEGER,
    latency_ms INTEGER,
    metadata TEXT,                      -- JSON object
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);
```

### detections

Records security detection signals.

```sql
CREATE TABLE detections (
    id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    detector_type TEXT NOT NULL,        -- dlp|injection|anomaly|policy
    detector_name TEXT NOT NULL,        -- Specific detector
    severity TEXT NOT NULL,             -- low|medium|high|critical
    confidence REAL,                    -- 0.0-1.0
    signals TEXT NOT NULL,              -- JSON array of signals
    raw_score REAL,
    threshold REAL,
    metadata TEXT,
    FOREIGN KEY (event_id) REFERENCES events(id)
);
```

### actions

Records enforcement actions taken.

```sql
CREATE TABLE actions (
    id TEXT PRIMARY KEY,
    detection_id TEXT,
    event_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    action_type TEXT NOT NULL,          -- allow|block|sanitize|quarantine|throttle
    policy_id TEXT,                     -- Policy that triggered action
    playbook_id TEXT,                   -- Playbook executed
    original_content TEXT,              -- Before action (redacted)
    modified_content TEXT,              -- After action (redacted)
    explanation TEXT,                   -- Human-readable explanation
    metadata TEXT,
    FOREIGN KEY (detection_id) REFERENCES detections(id),
    FOREIGN KEY (event_id) REFERENCES events(id)
);
```

### taint_labels

Tracks taint propagation.

```sql
CREATE TABLE taint_labels (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    source_type TEXT NOT NULL,          -- user_input|rag_doc|tool_output|model_response
    source_id TEXT NOT NULL,            -- Reference to source
    label TEXT NOT NULL,                -- Taint label (e.g., "pii", "external")
    confidence REAL,
    metadata TEXT
);
```

### taint_edges

Tracks data flow between tainted entities.

```sql
CREATE TABLE taint_edges (
    id TEXT PRIMARY KEY,
    from_label_id TEXT NOT NULL,
    to_label_id TEXT NOT NULL,
    edge_type TEXT NOT NULL,            -- propagate|transform|sink
    timestamp TEXT NOT NULL,
    metadata TEXT,
    FOREIGN KEY (from_label_id) REFERENCES taint_labels(id),
    FOREIGN KEY (to_label_id) REFERENCES taint_labels(id)
);
```

### explanations

Stores generated explanations.

```sql
CREATE TABLE explanations (
    id TEXT PRIMARY KEY,
    detection_id TEXT,
    action_id TEXT,
    timestamp TEXT NOT NULL,
    explanation_type TEXT NOT NULL,     -- shap|narrative|lineage
    content TEXT NOT NULL,              -- Explanation content
    metadata TEXT,
    FOREIGN KEY (detection_id) REFERENCES detections(id),
    FOREIGN KEY (action_id) REFERENCES actions(id)
);
```

## Indexes

```sql
CREATE INDEX idx_events_session ON events(session_id);
CREATE INDEX idx_events_timestamp ON events(timestamp);
CREATE INDEX idx_events_type ON events(event_type);
CREATE INDEX idx_detections_event ON detections(event_id);
CREATE INDEX idx_detections_severity ON detections(severity);
CREATE INDEX idx_actions_event ON actions(event_id);
CREATE INDEX idx_taint_source ON taint_labels(source_type, source_id);
```

## Export Formats

### JSONL (Events)

```json
{"id": "evt_123", "session_id": "sess_456", "timestamp": "2024-12-27T10:00:00Z", "event_type": "request", ...}
{"id": "evt_124", "session_id": "sess_456", "timestamp": "2024-12-27T10:00:01Z", "event_type": "detection", ...}
```

### CSV (Summary)

```csv
session_id,event_count,detection_count,action_count,first_event,last_event
sess_456,10,2,1,2024-12-27T10:00:00Z,2024-12-27T10:05:00Z
```

## Retention Policy

- Default: 30 days
- Configurable via `AIRS_RETENTION_DAYS`
- Cleanup job runs daily
- Export before deletion available
