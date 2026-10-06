import json
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.db.models import AIAnalysis, Alert, User
from app.db.session import get_db
from app.deps import require_roles
from app.schemas import AlertOut, AlertPage, AnalysisOut

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])
ANALYST_OR_ADMIN = require_roles("admin", "analyst")


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _load_list(text: str | None) -> list[str]:
    if not text:
        return []
    try:
        value = json.loads(text)
    except ValueError:
        return []
    return [str(v) for v in value] if isinstance(value, list) else []


def analysis_to_out(row: AIAnalysis, external_id: str) -> AnalysisOut:
    return AnalysisOut(
        id=row.id,
        alert_external_id=external_id,
        status=row.status,
        model=row.model,
        summary=row.summary,
        threat_assessment=row.threat_assessment,
        mitre_techniques=_load_list(row.mitre_techniques),
        business_impact=row.business_impact,
        confidence=row.confidence,
        confidence_explanation=row.confidence_explanation,
        recommendations=_load_list(row.recommendations),
        error_code=row.error_code,
        created_at=row.created_at,
    )


@router.get("", response_model=AlertPage)
def list_alerts(
    page: int = Query(1, ge=1, le=10_000),
    page_size: int = Query(25, ge=1, le=100),
    severity: Literal["critical", "high", "medium", "low"] | None = None,
    alert_status: Literal["New", "Investigating", "Closed"] | None = Query(None, alias="status"),
    q: str | None = Query(None, max_length=100),
    _user: User = Depends(ANALYST_OR_ADMIN),
    db: Session = Depends(get_db),
) -> AlertPage:
    stmt = select(Alert)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if alert_status:
        stmt = stmt.where(Alert.status == alert_status)
    if q:
        pattern = f"%{_escape_like(q.strip())}%"
        stmt = stmt.where(
            or_(
                Alert.rule.ilike(pattern, escape="\\"),
                Alert.host.ilike(pattern, escape="\\"),
                Alert.source_ip.ilike(pattern, escape="\\"),
                Alert.mitre.ilike(pattern, escape="\\"),
                Alert.external_id.ilike(pattern, escape="\\"),
            )
        )

    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(
        stmt.order_by(Alert.occurred_at.desc(), Alert.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return AlertPage(
        items=[AlertOut.model_validate(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{external_id}", response_model=AlertOut)
def get_alert(
    external_id: str,
    _user: User = Depends(ANALYST_OR_ADMIN),
    db: Session = Depends(get_db),
) -> AlertOut:
    alert = db.scalar(select(Alert).where(Alert.external_id == external_id))
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return AlertOut.model_validate(alert)


@router.get("/{external_id}/analyses", response_model=list[AnalysisOut])
def list_analyses(
    external_id: str,
    _user: User = Depends(ANALYST_OR_ADMIN),
    db: Session = Depends(get_db),
) -> list[AnalysisOut]:
    alert = db.scalar(select(Alert).where(Alert.external_id == external_id))
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    rows = db.scalars(
        select(AIAnalysis).where(AIAnalysis.alert_id == alert.id).order_by(AIAnalysis.created_at.desc())
    ).all()
    return [analysis_to_out(r, external_id) for r in rows]
