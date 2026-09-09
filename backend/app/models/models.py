from datetime import datetime, timezone
import uuid
from sqlalchemy import DateTime, Float, Integer, String, Text, ForeignKey, JSON, Boolean, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from app.db.session import Base

def now(): return datetime.now(timezone.utc)

class Investigation(Base):
    __tablename__ = "investigations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target: Mapped[str] = mapped_column(String(320), index=True)
    normalized_email: Mapped[str] = mapped_column(String(320), index=True)
    username: Mapped[str] = mapped_column(String(200))
    domain: Mapped[str] = mapped_column(String(253))
    status: Mapped[str] = mapped_column(String(32), default="queued")
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(16), nullable=True)
    privacy_mode: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    execution_token: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    execution_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    execution_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    execution_id: Mapped[str | None] = mapped_column(String(36), nullable=True, unique=True, index=True, default=lambda: str(uuid.uuid4()))

class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("investigation_id", "execution_id", "persistence_key", name="uq_findings_execution_persistence"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    execution_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    persistence_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source: Mapped[str] = mapped_column(String(120))
    source_url: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    finding_type: Mapped[str] = mapped_column(String(120), index=True)
    value: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    severity: Mapped[str] = mapped_column(String(16), default="info")
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    raw_reference: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

class ModuleRun(Base):
    __tablename__ = "module_runs"
    __table_args__ = (UniqueConstraint("investigation_id", "execution_id", "module", name="uq_module_runs_execution_module"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    execution_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    module: Mapped[str] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(24), default="queued")
    message: Mapped[str | None] = mapped_column(String(500), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

class GraphNode(Base):
    __tablename__ = "graph_nodes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    node_key: Mapped[str] = mapped_column(String(300))
    node_type: Mapped[str] = mapped_column(String(40))
    label: Mapped[str] = mapped_column(String(300))
    node_metadata: Mapped[dict | None] = mapped_column(JSON, nullable=True)

class GraphEdge(Base):
    __tablename__ = "graph_edges"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    source: Mapped[str] = mapped_column(String(300))
    target: Mapped[str] = mapped_column(String(300))
    relation: Mapped[str] = mapped_column(String(80))
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
