import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.models import AIAnalysis, Alert, User
from app.db.session import get_db
from app.deps import require_roles
from app.routers.alerts import analysis_to_out
from app.schemas import AnalysisOut
from app.services import audit, gemini

router = APIRouter(prefix="/api/v1/alerts", tags=["ai"])
ANALYST_OR_ADMIN = require_roles("admin", "analyst")


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.post("/{external_id}/analysis", response_model=AnalysisOut, status_code=201)
def run_analysis(
    external_id: str,
    request: Request,
    user: User = Depends(ANALYST_OR_ADMIN),
    db: Session = Depends(get_db),
) -> AnalysisOut:
    alert = db.scalar(select(Alert).where(Alert.external_id == external_id))
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    settings = get_settings()
    ip = _client_ip(request)

    # Usage control: cap AI calls per user per hour. Failed attempts count too.
    window_start = datetime.now(timezone.utc) - timedelta(hours=1)
    recent = db.scalar(
        select(func.count(AIAnalysis.id)).where(
            AIAnalysis.requested_by == user.id,
            AIAnalysis.created_at >= window_start,
        )
    ) or 0
    if recent >= settings.ai_max_analyses_per_user_hour:
        raise HTTPException(status_code=429, detail="AI analysis limit reached. Try again later.")

    # Only fields the analyst can already see are sent to the model.
    alert_payload = {
        "alert_id": alert.external_id,
        "rule": alert.rule,
        "severity": alert.severity,
        "host": alert.host,
        "source_ip": alert.source_ip,
        "mitre_hint": alert.mitre,
        "occurred_at": alert.occurred_at.isoformat(),
        "status": alert.status,
    }

    try:
        result = gemini.analyse_alert(alert_payload)
    except gemini.GeminiError as exc:
        row = AIAnalysis(
            alert_id=alert.id,
            requested_by=user.id,
            model=settings.gemini_model,
            status="error",
            error_code=exc.code,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        audit.record(db, "ai_analysis_failed", actor_id=user.id, target=external_id, detail=exc.code, ip=ip)
        raise HTTPException(
            status_code=503,
            detail={"message": "AI analysis is unavailable", "code": exc.code},
        )

    row = AIAnalysis(
        alert_id=alert.id,
        requested_by=user.id,
        model=settings.gemini_model,
        status="ok",
        summary=result.summary,
        threat_assessment=result.threat_assessment,
        mitre_techniques=json.dumps(result.mitre_techniques),
        business_impact=result.business_impact,
        confidence=result.confidence,
        confidence_explanation=result.confidence_explanation,
        recommendations=json.dumps(result.recommendations),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    audit.record(db, "ai_analysis", actor_id=user.id, target=external_id, ip=ip)
    return analysis_to_out(row, external_id)
