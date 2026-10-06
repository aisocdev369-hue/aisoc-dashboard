from datetime import datetime
from typing import Literal

from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=72)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    role: str


class UserOut(BaseModel):
    id: int
    email: str
    role: str
    is_active: bool

    model_config = {"from_attributes": True}


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=72)
    role: Literal["admin", "analyst"]


class AlertOut(BaseModel):
    external_id: str
    rule: str
    severity: str
    host: str
    source_ip: str
    mitre: str
    status: str
    occurred_at: datetime
    is_simulated: bool

    model_config = {"from_attributes": True}


class AlertPage(BaseModel):
    items: list[AlertOut]
    total: int
    page: int
    page_size: int


class AnalysisOut(BaseModel):
    id: int
    alert_external_id: str
    status: str
    model: str
    summary: str | None = None
    threat_assessment: str | None = None
    mitre_techniques: list[str] = []
    business_impact: str | None = None
    confidence: str | None = None
    confidence_explanation: str | None = None
    recommendations: list[str] = []
    error_code: str | None = None
    created_at: datetime


class AuditOut(BaseModel):
    id: int
    actor_id: int | None
    action: str
    target: str | None
    detail: str | None
    ip: str | None
    created_at: datetime

    model_config = {"from_attributes": True}
