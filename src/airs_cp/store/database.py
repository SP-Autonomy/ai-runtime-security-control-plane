"""
Evidence Store Database

SQLite-based storage for security events, detections, actions,
taint tracking, and explanations.
"""

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

from airs_cp.store.models import (
    Action,
    Detection,
    Event,
    Explanation,
    Session,
    TaintEdge,
    TaintLabel,
)


# SQL Schema
SCHEMA = """
-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    user_id TEXT,
    tags TEXT,
    metadata TEXT,
    status TEXT DEFAULT 'active'
);

-- Events table
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    direction TEXT,
    content TEXT,
    content_hash TEXT,
    provider TEXT,
    model TEXT,
    tokens_in INTEGER,
    tokens_out INTEGER,
    latency_ms INTEGER,
    metadata TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

-- Detections table
CREATE TABLE IF NOT EXISTS detections (
    id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    detector_type TEXT NOT NULL,
    detector_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL,
    signals TEXT NOT NULL,
    raw_score REAL,
    threshold REAL,
    metadata TEXT,
    FOREIGN KEY (event_id) REFERENCES events(id)
);

-- Actions table
CREATE TABLE IF NOT EXISTS actions (
    id TEXT PRIMARY KEY,
    detection_id TEXT,
    event_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    action_type TEXT NOT NULL,
    policy_id TEXT,
    playbook_id TEXT,
    original_content TEXT,
    modified_content TEXT,
    explanation TEXT,
    metadata TEXT,
    FOREIGN KEY (detection_id) REFERENCES detections(id),
    FOREIGN KEY (event_id) REFERENCES events(id)
);

-- Taint labels table
CREATE TABLE IF NOT EXISTS taint_labels (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_id TEXT NOT NULL,
    sensitivity TEXT NOT NULL,
    label TEXT NOT NULL,
    content_hash TEXT,
    confidence REAL,
    metadata TEXT
);

-- Taint edges table
CREATE TABLE IF NOT EXISTS taint_edges (
    id TEXT PRIMARY KEY,
    from_label_id TEXT NOT NULL,
    to_label_id TEXT NOT NULL,
    edge_type TEXT NOT NULL,
    operation TEXT,
    timestamp TEXT NOT NULL,
    metadata TEXT,
    FOREIGN KEY (from_label_id) REFERENCES taint_labels(id),
    FOREIGN KEY (to_label_id) REFERENCES taint_labels(id)
);

-- Explanations table
CREATE TABLE IF NOT EXISTS explanations (
    id TEXT PRIMARY KEY,
    detection_id TEXT,
    action_id TEXT,
    timestamp TEXT NOT NULL,
    explanation_type TEXT NOT NULL,
    content TEXT NOT NULL,
    metadata TEXT,
    FOREIGN KEY (detection_id) REFERENCES detections(id),
    FOREIGN KEY (action_id) REFERENCES actions(id)
);

-- Agent registrations table (for observability)
CREATE TABLE IF NOT EXISTS agent_registrations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    purpose TEXT,
    allowed_tools TEXT,
    risk_tolerance TEXT DEFAULT 'medium',
    max_tool_calls INTEGER DEFAULT 10,
    typical_tool_sequence TEXT,
    created_at TEXT NOT NULL,
    metadata TEXT
);

-- Tool invocations table (for observability)
CREATE TABLE IF NOT EXISTS tool_invocations (
    id TEXT PRIMARY KEY,
    session_id TEXT,
    agent_id TEXT,
    tool_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    reasoning TEXT,
    user_intent TEXT,
    input_args TEXT,
    status TEXT DEFAULT 'success',
    was_blocked INTEGER DEFAULT 0,
    block_reason TEXT,
    deviation_score REAL DEFAULT 0.0,
    deviation_reasons TEXT,
    metadata TEXT
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_detections_event ON detections(event_id);
CREATE INDEX IF NOT EXISTS idx_detections_severity ON detections(severity);
CREATE INDEX IF NOT EXISTS idx_actions_event ON actions(event_id);
CREATE INDEX IF NOT EXISTS idx_taint_source ON taint_labels(source_type, source_id);
CREATE INDEX IF NOT EXISTS idx_taint_edges_from ON taint_edges(from_label_id);
CREATE INDEX IF NOT EXISTS idx_taint_edges_to ON taint_edges(to_label_id);
CREATE INDEX IF NOT EXISTS idx_invocations_session ON tool_invocations(session_id);
CREATE INDEX IF NOT EXISTS idx_invocations_agent ON tool_invocations(agent_id);
CREATE INDEX IF NOT EXISTS idx_invocations_timestamp ON tool_invocations(timestamp);
"""


class EvidenceStore:
    """
    SQLite-based evidence store for security data.
    
    Provides CRUD operations for all security-related data including
    sessions, events, detections, actions, taint tracking, and explanations.
    """
    
    def __init__(self, db_path: str = "./data/evidence.db"):
        """
        Initialize the evidence store.
        
        Args:
            db_path: Path to SQLite database file.
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
    
    def _init_db(self) -> None:
        """Initialize database schema."""
        with self._get_connection() as conn:
            conn.executescript(SCHEMA)
            conn.commit()
    
    @contextmanager
    def _get_connection(self) -> Iterator[sqlite3.Connection]:
        """Get database connection with row factory."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    # === Session Operations ===
    
    def create_session(self, session: Session) -> Session:
        """Create a new session."""
        with self._get_connection() as conn:
            data = session.to_dict()
            conn.execute(
                """INSERT INTO sessions 
                   (id, created_at, updated_at, user_id, tags, metadata, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (data["id"], data["created_at"], data["updated_at"],
                 data["user_id"], data["tags"], data["metadata"], data["status"])
            )
            conn.commit()
        return session
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """Get session by ID."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE id = ?", (session_id,)
            ).fetchone()
            if row:
                return Session(
                    id=row["id"],
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                    user_id=row["user_id"],
                    tags=json.loads(row["tags"]) if row["tags"] else [],
                    metadata=json.loads(row["metadata"]) if row["metadata"] else {},
                    status=row["status"],
                )
        return None
    
    def update_session_status(self, session_id: str, status: str) -> None:
        """Update session status."""
        from airs_cp.store.models import now_iso
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE sessions SET status = ?, updated_at = ? WHERE id = ?",
                (status, now_iso(), session_id)
            )
            conn.commit()
    
    # === Event Operations ===
    
    def create_event(self, event: Event) -> Event:
        """Create a new event."""
        with self._get_connection() as conn:
            data = event.to_dict()
            conn.execute(
                """INSERT INTO events 
                   (id, session_id, timestamp, event_type, direction, content,
                    content_hash, provider, model, tokens_in, tokens_out,
                    latency_ms, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (data["id"], data["session_id"], data["timestamp"],
                 data["event_type"], data["direction"], data["content"],
                 data["content_hash"], data["provider"], data["model"],
                 data["tokens_in"], data["tokens_out"], data["latency_ms"],
                 data["metadata"])
            )
            conn.commit()
        return event
    
    def get_event(self, event_id: str) -> Optional[Event]:
        """Get event by ID."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM events WHERE id = ?", (event_id,)
            ).fetchone()
            if row:
                return self._row_to_event(row)
        return None
    
    def get_session_events(self, session_id: str) -> list[Event]:
        """Get all events for a session."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM events WHERE session_id = ? ORDER BY timestamp",
                (session_id,)
            ).fetchall()
            return [self._row_to_event(row) for row in rows]
    
    def _row_to_event(self, row: sqlite3.Row) -> Event:
        """Convert database row to Event object."""
        from airs_cp.store.models import EventType
        return Event(
            id=row["id"],
            session_id=row["session_id"],
            timestamp=row["timestamp"],
            event_type=EventType(row["event_type"]),
            direction=row["direction"],
            content=row["content"],
            content_hash=row["content_hash"],
            provider=row["provider"],
            model=row["model"],
            tokens_in=row["tokens_in"],
            tokens_out=row["tokens_out"],
            latency_ms=row["latency_ms"],
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
        )
    
    # === Detection Operations ===
    
    def create_detection(self, detection: Detection) -> Detection:
        """Create a new detection."""
        with self._get_connection() as conn:
            data = detection.to_dict()
            conn.execute(
                """INSERT INTO detections 
                   (id, event_id, timestamp, detector_type, detector_name,
                    severity, confidence, signals, raw_score, threshold, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (data["id"], data["event_id"], data["timestamp"],
                 data["detector_type"], data["detector_name"],
                 data["severity"], data["confidence"], data["signals"],
                 data["raw_score"], data["threshold"], data["metadata"])
            )
            conn.commit()
        return detection
    
    def get_event_detections(self, event_id: str) -> list[Detection]:
        """Get all detections for an event."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM detections WHERE event_id = ?", (event_id,)
            ).fetchall()
            return [self._row_to_detection(row) for row in rows]
    
    def _row_to_detection(self, row: sqlite3.Row) -> Detection:
        """Convert database row to Detection object."""
        from airs_cp.store.models import DetectorType, Severity
        return Detection(
            id=row["id"],
            event_id=row["event_id"],
            timestamp=row["timestamp"],
            detector_type=DetectorType(row["detector_type"]),
            detector_name=row["detector_name"],
            severity=Severity(row["severity"]),
            confidence=row["confidence"],
            signals=json.loads(row["signals"]) if row["signals"] else [],
            raw_score=row["raw_score"],
            threshold=row["threshold"],
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
        )
    
    # === Action Operations ===
    
    def create_action(self, action: Action) -> Action:
        """Create a new action."""
        with self._get_connection() as conn:
            data = action.to_dict()
            conn.execute(
                """INSERT INTO actions 
                   (id, detection_id, event_id, timestamp, action_type,
                    policy_id, playbook_id, original_content, modified_content,
                    explanation, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (data["id"], data["detection_id"], data["event_id"],
                 data["timestamp"], data["action_type"], data["policy_id"],
                 data["playbook_id"], data["original_content"],
                 data["modified_content"], data["explanation"], data["metadata"])
            )
            conn.commit()
        return action
    
    def get_event_actions(self, event_id: str) -> list[Action]:
        """Get all actions for an event."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM actions WHERE event_id = ?", (event_id,)
            ).fetchall()
            return [self._row_to_action(row) for row in rows]
    
    def _row_to_action(self, row: sqlite3.Row) -> Action:
        """Convert database row to Action object."""
        from airs_cp.store.models import ActionType
        return Action(
            id=row["id"],
            detection_id=row["detection_id"],
            event_id=row["event_id"],
            timestamp=row["timestamp"],
            action_type=ActionType(row["action_type"]),
            policy_id=row["policy_id"],
            playbook_id=row["playbook_id"],
            original_content=row["original_content"],
            modified_content=row["modified_content"],
            explanation=row["explanation"],
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
        )
    
    # === Taint Operations ===
    
    def create_taint_label(self, label: TaintLabel) -> TaintLabel:
        """Create a new taint label."""
        with self._get_connection() as conn:
            data = label.to_dict()
            conn.execute(
                """INSERT INTO taint_labels 
                   (id, created_at, source_type, source_id, sensitivity,
                    label, content_hash, confidence, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (data["id"], data["created_at"], data["source_type"],
                 data["source_id"], data["sensitivity"], data["label"],
                 data["content_hash"], data["confidence"], data["metadata"])
            )
            conn.commit()
        return label
    
    def create_taint_edge(self, edge: TaintEdge) -> TaintEdge:
        """Create a new taint edge."""
        with self._get_connection() as conn:
            data = edge.to_dict()
            conn.execute(
                """INSERT INTO taint_edges 
                   (id, from_label_id, to_label_id, edge_type, operation,
                    timestamp, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (data["id"], data["from_label_id"], data["to_label_id"],
                 data["edge_type"], data["operation"], data["timestamp"],
                 data["metadata"])
            )
            conn.commit()
        return edge
    
    def get_taint_lineage(self, label_id: str) -> dict[str, Any]:
        """Get taint lineage graph for a label."""
        nodes = []
        edges = []
        visited = set()
        
        def traverse(lid: str, direction: str = "both"):
            if lid in visited:
                return
            visited.add(lid)
            
            with self._get_connection() as conn:
                # Get the label node
                row = conn.execute(
                    "SELECT * FROM taint_labels WHERE id = ?", (lid,)
                ).fetchone()
                if row:
                    nodes.append({
                        "id": row["id"],
                        "source_type": row["source_type"],
                        "source_id": row["source_id"],
                        "sensitivity": row["sensitivity"],
                        "label": row["label"],
                        "created_at": row["created_at"],
                    })
                
                # Get outgoing edges
                if direction in ("both", "forward"):
                    out_edges = conn.execute(
                        "SELECT * FROM taint_edges WHERE from_label_id = ?", (lid,)
                    ).fetchall()
                    for edge in out_edges:
                        edges.append({
                            "id": edge["id"],
                            "from": edge["from_label_id"],
                            "to": edge["to_label_id"],
                            "type": edge["edge_type"],
                            "operation": edge["operation"],
                        })
                        traverse(edge["to_label_id"], "forward")
                
                # Get incoming edges
                if direction in ("both", "backward"):
                    in_edges = conn.execute(
                        "SELECT * FROM taint_edges WHERE to_label_id = ?", (lid,)
                    ).fetchall()
                    for edge in in_edges:
                        edges.append({
                            "id": edge["id"],
                            "from": edge["from_label_id"],
                            "to": edge["to_label_id"],
                            "type": edge["edge_type"],
                            "operation": edge["operation"],
                        })
                        traverse(edge["from_label_id"], "backward")
        
        traverse(label_id)
        return {"nodes": nodes, "edges": edges}
    
    # === Explanation Operations ===
    
    def create_explanation(self, explanation: Explanation) -> Explanation:
        """Create a new explanation."""
        with self._get_connection() as conn:
            data = explanation.to_dict()
            conn.execute(
                """INSERT INTO explanations 
                   (id, detection_id, action_id, timestamp, explanation_type,
                    content, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (data["id"], data["detection_id"], data["action_id"],
                 data["timestamp"], data["explanation_type"],
                 data["content"], data["metadata"])
            )
            conn.commit()
        return explanation
    
    def get_detection_explanation(self, detection_id: str) -> Optional[Explanation]:
        """Get explanation for a detection."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM explanations WHERE detection_id = ?",
                (detection_id,)
            ).fetchone()
            if row:
                return self._row_to_explanation(row)
        return None
    
    def _row_to_explanation(self, row: sqlite3.Row) -> Explanation:
        """Convert database row to Explanation object."""
        from airs_cp.store.models import ExplanationType
        return Explanation(
            id=row["id"],
            detection_id=row["detection_id"],
            action_id=row["action_id"],
            timestamp=row["timestamp"],
            explanation_type=ExplanationType(row["explanation_type"]),
            content=json.loads(row["content"]) if row["content"] else {},
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
        )
    
    # === Query Operations ===
    
    def get_recent_detections(
        self,
        limit: int = 100,
        severity: Optional[str] = None
    ) -> list[Detection]:
        """Get recent detections, optionally filtered by severity."""
        with self._get_connection() as conn:
            if severity:
                rows = conn.execute(
                    """SELECT * FROM detections 
                       WHERE severity = ?
                       ORDER BY timestamp DESC LIMIT ?""",
                    (severity, limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT * FROM detections 
                       ORDER BY timestamp DESC LIMIT ?""",
                    (limit,)
                ).fetchall()
            return [self._row_to_detection(row) for row in rows]
    
    def get_session_summary(self, session_id: str) -> dict[str, Any]:
        """Get summary statistics for a session."""
        with self._get_connection() as conn:
            event_count = conn.execute(
                "SELECT COUNT(*) FROM events WHERE session_id = ?",
                (session_id,)
            ).fetchone()[0]
            
            detection_count = conn.execute(
                """SELECT COUNT(*) FROM detections d
                   JOIN events e ON d.event_id = e.id
                   WHERE e.session_id = ?""",
                (session_id,)
            ).fetchone()[0]
            
            action_count = conn.execute(
                """SELECT COUNT(*) FROM actions a
                   JOIN events e ON a.event_id = e.id
                   WHERE e.session_id = ?""",
                (session_id,)
            ).fetchone()[0]
            
            return {
                "session_id": session_id,
                "event_count": event_count,
                "detection_count": detection_count,
                "action_count": action_count,
            }
    
    # === Agent Observability Operations ===
    
    def save_agent_registration(
        self,
        agent_id: str,
        name: str,
        description: str = "",
        purpose: str = "",
        allowed_tools: list[str] = None,
        risk_tolerance: str = "medium",
        max_tool_calls: int = 10,
        typical_tool_sequence: list[str] = None,
        metadata: dict = None,
    ) -> str:
        """Save or update an agent registration."""
        from datetime import datetime
        
        with self._get_connection() as conn:
            # Check if exists
            existing = conn.execute(
                "SELECT id FROM agent_registrations WHERE id = ?",
                (agent_id,)
            ).fetchone()
            
            if existing:
                # Update
                conn.execute(
                    """UPDATE agent_registrations SET
                       name = ?, description = ?, purpose = ?,
                       allowed_tools = ?, risk_tolerance = ?,
                       max_tool_calls = ?, typical_tool_sequence = ?,
                       metadata = ?
                       WHERE id = ?""",
                    (
                        name, description, purpose,
                        json.dumps(allowed_tools or []),
                        risk_tolerance, max_tool_calls,
                        json.dumps(typical_tool_sequence or []),
                        json.dumps(metadata or {}),
                        agent_id,
                    )
                )
            else:
                # Insert
                conn.execute(
                    """INSERT INTO agent_registrations
                       (id, name, description, purpose, allowed_tools,
                        risk_tolerance, max_tool_calls, typical_tool_sequence,
                        created_at, metadata)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        agent_id, name, description, purpose,
                        json.dumps(allowed_tools or []),
                        risk_tolerance, max_tool_calls,
                        json.dumps(typical_tool_sequence or []),
                        datetime.utcnow().isoformat(),
                        json.dumps(metadata or {}),
                    )
                )
            conn.commit()
        return agent_id
    
    def get_agent_registrations(self) -> list[dict]:
        """Get all registered agents."""
        with self._get_connection() as conn:
            rows = conn.execute(
                """SELECT id, name, description, purpose, allowed_tools,
                          risk_tolerance, max_tool_calls, typical_tool_sequence,
                          created_at, metadata
                   FROM agent_registrations
                   ORDER BY created_at DESC"""
            ).fetchall()
            
            agents = []
            for row in rows:
                agents.append({
                    "id": row[0],
                    "name": row[1],
                    "description": row[2],
                    "purpose": row[3],
                    "allowed_tools": json.loads(row[4]) if row[4] else [],
                    "risk_tolerance": row[5],
                    "max_tool_calls": row[6],
                    "typical_tool_sequence": json.loads(row[7]) if row[7] else [],
                    "created_at": row[8],
                    "metadata": json.loads(row[9]) if row[9] else {},
                })
            return agents
    
    def save_tool_invocation(
        self,
        invocation_id: str,
        tool_id: str,
        session_id: str = "",
        agent_id: str = "",
        reasoning: str = "",
        user_intent: str = "",
        input_args: dict = None,
        status: str = "success",
        was_blocked: bool = False,
        block_reason: str = "",
        deviation_score: float = 0.0,
        deviation_reasons: list[str] = None,
        metadata: dict = None,
    ) -> str:
        """Save a tool invocation."""
        from datetime import datetime
        
        with self._get_connection() as conn:
            conn.execute(
                """INSERT INTO tool_invocations
                   (id, session_id, agent_id, tool_id, timestamp,
                    reasoning, user_intent, input_args, status,
                    was_blocked, block_reason, deviation_score,
                    deviation_reasons, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    invocation_id, session_id, agent_id, tool_id,
                    datetime.utcnow().isoformat(),
                    reasoning, user_intent,
                    json.dumps(input_args or {}),
                    status, 1 if was_blocked else 0, block_reason,
                    deviation_score,
                    json.dumps(deviation_reasons or []),
                    json.dumps(metadata or {}),
                )
            )
            conn.commit()
        return invocation_id
    
    def get_recent_invocations(self, limit: int = 50) -> list[dict]:
        """Get recent tool invocations."""
        with self._get_connection() as conn:
            rows = conn.execute(
                """SELECT id, session_id, agent_id, tool_id, timestamp,
                          reasoning, user_intent, input_args, status,
                          was_blocked, block_reason, deviation_score,
                          deviation_reasons, metadata
                   FROM tool_invocations
                   ORDER BY timestamp DESC
                   LIMIT ?""",
                (limit,)
            ).fetchall()
            
            invocations = []
            for row in rows:
                invocations.append({
                    "id": row[0],
                    "session_id": row[1],
                    "agent_id": row[2],
                    "tool_id": row[3],
                    "timestamp": row[4],
                    "reasoning": row[5],
                    "user_intent": row[6],
                    "input_args": json.loads(row[7]) if row[7] else {},
                    "status": row[8],
                    "was_blocked": bool(row[9]),
                    "block_reason": row[10],
                    "deviation_score": row[11],
                    "deviation_reasons": json.loads(row[12]) if row[12] else [],
                    "metadata": json.loads(row[13]) if row[13] else {},
                })
            return invocations
    
    def get_invocations_with_deviations(self, min_score: float = 0.3) -> list[dict]:
        """Get invocations with deviation scores above threshold."""
        with self._get_connection() as conn:
            rows = conn.execute(
                """SELECT id, session_id, agent_id, tool_id, timestamp,
                          reasoning, user_intent, deviation_score, deviation_reasons
                   FROM tool_invocations
                   WHERE deviation_score >= ?
                   ORDER BY deviation_score DESC, timestamp DESC
                   LIMIT 50""",
                (min_score,)
            ).fetchall()
            
            return [
                {
                    "id": row[0],
                    "session_id": row[1],
                    "agent_id": row[2],
                    "tool_id": row[3],
                    "timestamp": row[4],
                    "reasoning": row[5],
                    "user_intent": row[6],
                    "deviation_score": row[7],
                    "deviation_reasons": json.loads(row[8]) if row[8] else [],
                }
                for row in rows
            ]
    
    def get_invocation_stats(self) -> dict:
        """Get invocation statistics."""
        with self._get_connection() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM tool_invocations"
            ).fetchone()[0]
            
            deviations = conn.execute(
                "SELECT COUNT(*) FROM tool_invocations WHERE deviation_score > 0.3"
            ).fetchone()[0]
            
            by_agent = {}
            rows = conn.execute(
                """SELECT agent_id, COUNT(*) FROM tool_invocations
                   WHERE agent_id != '' GROUP BY agent_id"""
            ).fetchall()
            for row in rows:
                by_agent[row[0]] = row[1]
            
            by_tool = {}
            rows = conn.execute(
                """SELECT tool_id, COUNT(*) FROM tool_invocations
                   GROUP BY tool_id"""
            ).fetchall()
            for row in rows:
                by_tool[row[0]] = row[1]
            
            return {
                "total": total,
                "deviations": deviations,
                "by_agent": by_agent,
                "by_tool": by_tool,
            }
    
    # === Export Operations ===
    
    def export_session_jsonl(self, session_id: str) -> str:
        """Export session data as JSONL."""
        lines = []
        
        session = self.get_session(session_id)
        if session:
            lines.append(json.dumps({"type": "session", **session.to_dict()}))
        
        events = self.get_session_events(session_id)
        for event in events:
            lines.append(json.dumps({"type": "event", **event.to_dict()}))
            
            detections = self.get_event_detections(event.id)
            for det in detections:
                lines.append(json.dumps({"type": "detection", **det.to_dict()}))
            
            actions = self.get_event_actions(event.id)
            for act in actions:
                lines.append(json.dumps({"type": "action", **act.to_dict()}))
        
        return "\n".join(lines)


# Global store instance
_store: Optional[EvidenceStore] = None


def get_store(db_path: Optional[str] = None) -> EvidenceStore:
    """Get the global evidence store instance."""
    global _store
    if _store is None:
        from airs_cp.config import settings
        path = db_path or settings.db_path
        _store = EvidenceStore(path)
    return _store
