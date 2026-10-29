from datetime import datetime
from typing import Literal

from pydantic import BaseModel, EmailStr, Field, field_validator


def _validate_bcrypt_password(password: str) -> str:
    if len(password.encode("utf-8")) > 72:
        raise ValueError("Password must be at most 72 bytes")
    return password


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=72)

    @field_validator("password")
    @classmethod
    def password_fits_bcrypt(cls, password: str) -> str:
        return _validate_bcrypt_password(password)


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=72)

    model_config = {"extra": "forbid"}

    @field_validator("password")
    @classmethod
    def password_fits_bcrypt(cls, password: str) -> str:
        return _validate_bcrypt_password(password)


class GoogleCredentialRequest(BaseModel):
    credential: str = Field(min_length=1, max_length=8192)


class GoogleAuthConfig(BaseModel):
    enabled: bool
    client_id: str | None = None


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

    @field_validator("password")
    @classmethod
    def password_fits_bcrypt(cls, password: str) -> str:
        return _validate_bcrypt_password(password)


class UserRoleUpdate(BaseModel):
    role: Literal["admin", "analyst"]


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=72)
    new_password: str = Field(min_length=12, max_length=72)

    @field_validator("current_password", "new_password")
    @classmethod
    def password_fits_bcrypt(cls, password: str) -> str:
        return _validate_bcrypt_password(password)


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
    mitre_techniques: list[str] = Field(default_factory=list)
    business_impact: str | None = None
    confidence: str | None = None
    confidence_explanation: str | None = None
    recommendations: list[str] = Field(default_factory=list)
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
