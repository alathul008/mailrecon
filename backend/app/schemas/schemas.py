from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class InvestigationCreate(BaseModel):
    email: EmailStr
    privacy_mode: bool = False
    external_provider_disclosure: bool = True


class HealthOut(BaseModel):
    status: str
    service: str


class ProviderOut(BaseModel):
    name: str
    category: str
    status: str
    configuration: str
    supported: bool
    discovery_methods: list[str]
    external_network: bool
    account_discovery: bool
    orchestrated: bool


class CreateInvestigationOut(BaseModel):
    id: int
    status: str
    external_provider_disclosure: bool


class DemoOut(BaseModel):
    id: int
    status: str
    demo: bool


class InvestigationSummaryOut(BaseModel):
    id: int
    target: str
    status: str
    risk_score: int | None
    risk_level: str | None
    created_at: datetime
    external_provider_disclosure: bool


class ModuleOut(BaseModel):
    module: str
    status: str
    message: str | None = None
    execution_id: str | None = None
    execution_attempt_id: str | None = None
    current: bool = False
    started_at: datetime | None = None
    finished_at: datetime | None = None


class FindingOut(BaseModel):
    id: int
    source: str
    source_url: str | None
    finding_type: str
    value: str
    confidence: float
    evidence_state: str | None
    severity: str
    execution_id: str | None
    execution_attempt_id: str | None
    current_attempt: bool = False
    historical_attempt: bool = False
    first_seen: datetime | None
    last_seen: datetime | None
    collected_at: datetime
    notes: str | None


class InvestigationOut(BaseModel):
    id: int
    target: str
    username: str
    domain: str
    status: str
    risk_score: int | None
    risk_level: str | None
    privacy_mode: bool
    external_provider_disclosure: bool
    created_at: datetime
    completed_at: datetime | None
    execution_id: str | None
    execution_attempt_id: str | None
    modules: list[ModuleOut] = Field(default_factory=list)
    findings: list[FindingOut] = Field(default_factory=list)


class RiskFactorOut(BaseModel):
    reason: str
    delta: int | None
    notes: str | None = None


class RiskOut(BaseModel):
    score: int | None
    level: str | None
    dimensions: dict[str, int]
    factors: list[RiskFactorOut]


class TimelineEventOut(BaseModel):
    id: int
    timestamp: datetime | None
    last_seen: datetime | None
    collected_at: datetime
    kind: str
    label: str
    source: str
    value: str
    severity: str
    confidence: float
    evidence_state: str | None
    execution_attempt_id: str | None
    current_attempt: bool = False


class GraphNodeOut(BaseModel):
    id: str
    type: str
    label: str
    metadata: dict | None = None


class GraphEdgeOut(BaseModel):
    source: str
    target: str
    relation: str
    confidence: float


class GraphProvenanceOut(BaseModel):
    type: str
    execution_id: str | None
    execution_attempt_id: str | None
    attempt_status: str | None


class GraphOut(BaseModel):
    semantics: str
    provenance: GraphProvenanceOut
    nodes: list[GraphNodeOut]
    edges: list[GraphEdgeOut]


class DeleteInvestigationOut(BaseModel):
    id: int
    status: str


class CorrelationRelationshipOut(BaseModel):
    source: str
    target: str
    relationship: str
    evidence_state: str
    confidence: float
    supporting_finding_ids: list[int]
    explanation: str
    limitations: str


class CorrelationConflictOut(BaseModel):
    finding_type: str
    values: list[str]
    provider_sources: list[str]
    finding_ids: list[int]
    explanation: str


class CorrelationOut(BaseModel):
    target_email: str | None
    domain: str | None
    relationships: list[CorrelationRelationshipOut]
    conflicts: list[CorrelationConflictOut]
    semantics: dict[str, str]
    investigation_id: int
    execution_id: str | None
    execution_attempt_id: str | None
    provenance: dict[str, str | None]


class ServiceCatalogOut(BaseModel):
    service: str
    category: str
    supported: bool
    provider: str | None
    discovery_methods: list[str]


class ProviderExecutionStatusOut(BaseModel):
    provider: str
    status: str
    checked_at: datetime | None
    message: str | None
    finding_id: int
    execution_id: str | None
    execution_attempt_id: str | None


class AccountDiscoveryEvidenceOut(BaseModel):
    finding_id: int | None
    finding_type: str
    evidence_state: str | None
    confidence: float | None
    source: str | None
    source_url: str | None
    notes: str | None


class AccountDiscoveryServiceOut(BaseModel):
    category: str
    service: str
    status: str
    supported: bool
    discovery_methods: list[str]
    identifier: str | None
    confidence: float | None
    provider_status: str | None
    checked_at: datetime | None
    evidence: list[AccountDiscoveryEvidenceOut]


class AccountDiscoveryOut(BaseModel):
    investigation_id: int
    target: str
    normalized_email: str | None
    username: str | None
    domain: str | None
    execution_id: str | None
    execution_attempt_id: str | None
    provider_execution_status: list[ProviderExecutionStatusOut]
    semantics: dict[str, str]
    services: list[AccountDiscoveryServiceOut]
