from datetime import datetime
from pydantic import BaseModel, EmailStr

class InvestigationCreate(BaseModel):
    email: EmailStr
    privacy_mode: bool = False
    external_provider_disclosure: bool = False

class ModuleOut(BaseModel):
    module: str
    status: str
    message: str | None = None

class FindingOut(BaseModel):
    id: int
    source: str
    source_url: str | None
    finding_type: str
    value: str
    confidence: float
    severity: str
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
    created_at: datetime
    completed_at: datetime | None
    modules: list[ModuleOut] = []
    findings: list[FindingOut] = []
