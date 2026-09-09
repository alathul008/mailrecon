from datetime import datetime, timezone
import uuid
from sqlalchemy import DateTime, Float, Integer, String, Text, ForeignKey, ForeignKeyConstraint, JSON, Boolean, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from app.db.session import Base

def now(): return datetime.now(timezone.utc)

class Investigation(Base):
    __tablename__ = "investigations"
    __table_args__ = (ForeignKeyConstraint(["id", "execution_attempt_id"], ["execution_attempts.investigation_id", "execution_attempts.execution_attempt_id"], name="fk_investigations_execution_attempt_investigation"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target: Mapped[str] = mapped_column(String(320), index=True)
    normalized_email: Mapped[str] = mapped_column(String(320), index=True)
    username: Mapped[str] = mapped_column(String(200))
    domain: Mapped[str] = mapped_column(String(253))
    status: Mapped[str] = mapped_column(String(32), default="queued")
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(16), nullable=True)
    privacy_mode: Mapped[bool] = mapped_column(Boolean, default=False)
    external_provider_disclosure: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    execution_token: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    execution_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    execution_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    execution_id: Mapped[str | None] = mapped_column(String(36), nullable=True, unique=True, index=True, default=lambda: str(uuid.uuid4()))
    execution_attempt_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)

class ExecutionAttempt(Base):
    __tablename__ = "execution_attempts"
    __table_args__ = (UniqueConstraint("investigation_id", "execution_attempt_id", name="uq_execution_attempt_identity"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    execution_id: Mapped[str] = mapped_column(String(36), index=True)
    execution_attempt_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(24), default="running")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    recovered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    recovery_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)

class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (ForeignKeyConstraint(["investigation_id", "execution_attempt_id"], ["execution_attempts.investigation_id", "execution_attempts.execution_attempt_id"], name="fk_findings_execution_attempt_investigation"), UniqueConstraint("investigation_id", "execution_id", "persistence_key", name="uq_findings_execution_persistence"))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    execution_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    execution_attempt_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    persistence_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source: Mapped[str] = mapped_column(String(120))
    source_url: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    finding_type: Mapped[str] = mapped_column(String(120), index=True)
    value: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    severity: Mapped[str] = mapped_column(String(16), default="info")
    evidence_state: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    raw_reference: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

class ModuleRun(Base):
    __tablename__ = "module_runs"
    __table_args__ = (ForeignKeyConstraint(["investigation_id", "execution_attempt_id"], ["execution_attempts.investigation_id", "execution_attempts.execution_attempt_id"], name="fk_module_runs_execution_attempt_investigation"), UniqueConstraint("investigation_id", "execution_attempt_id", "module", name="uq_module_runs_attempt_module"))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    execution_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    execution_attempt_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    module: Mapped[str] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(24), default="queued")
    message: Mapped[str | None] = mapped_column(String(500), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

class GraphNode(Base):
    __tablename__ = "graph_nodes"
    __table_args__ = (UniqueConstraint("investigation_id", "node_key", name="uq_graph_nodes_investigation_node_key"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    node_key: Mapped[str] = mapped_column(String(300))
    node_type: Mapped[str] = mapped_column(String(40))
    label: Mapped[str] = mapped_column(String(300))
    node_metadata: Mapped[dict | None] = mapped_column(JSON, nullable=True)

class GraphEdge(Base):
    __tablename__ = "graph_edges"
    __table_args__ = (UniqueConstraint("investigation_id", "source", "target", "relation", name="uq_graph_edges_investigation_identity"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    source: Mapped[str] = mapped_column(String(300))
    target: Mapped[str] = mapped_column(String(300))
    relation: Mapped[str] = mapped_column(String(300))
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
