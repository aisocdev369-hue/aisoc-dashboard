import hashlib
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Alert, Endpoint, EndpointEvent, User
from app.db.session import get_db
from app.deps import get_current_endpoint, require_roles
from app.schemas import IngestRequest, IngestResult, SourceHealthOut
from app.services.event_mapping import build_alert_fields

router = APIRouter(prefix="/api/v1", tags=["sources"])
ANALYST_OR_ADMIN = require_roles("admin", "analyst")

# An endpoint that hasn't checked in within this window shows as "stale" rather than "online".
STALE_AFTER = timedelta(minutes=10)


def _external_id(endpoint: Endpoint, client_event_id: str) -> str:
    # A short deterministic hash, not a naive truncation: Alert.external_id is capped at 64
    # chars, and truncating "AGENT-<hostname>-<client_event_id>" directly could make two
    # different events collide onto the same id for a long hostname. Same inputs always
    # hash the same way, so retried deliveries still dedup correctly.
    digest = hashlib.sha256(f"{endpoint.hostname}:{client_event_id}".encode("utf-8")).hexdigest()[:40]
    return f"AGENT-{digest}"


@router.post("/ingest", response_model=IngestResult)
def ingest(
    body: IngestRequest,
    endpoint: Endpoint = Depends(get_current_endpoint),
    db: Session = Depends(get_db),
) -> IngestResult:
    """Accepts a batch of events from one registered Windows 11 or Linux agent."""
    endpoint.last_seen_at = datetime.now(timezone.utc)
    alerts_created = 0

    for event in body.events:
        external_id = _external_id(endpoint, event.client_event_id)
        existing_alert_id = db.scalar(select(Alert.id).where(Alert.external_id == external_id))

        if existing_alert_id is None:
            alert = Alert(external_id=external_id, is_simulated=False, **build_alert_fields(endpoint, event))
            db.add(alert)
            db.flush()  # assign alert.id
            alerts_created += 1
            alert_id = alert.id
        else:
            # Already ingested (agent retry) — record the raw event again but don't double-alert.
            alert_id = existing_alert_id

        db.add(
            EndpointEvent(
                endpoint_id=endpoint.id,
                client_event_id=event.client_event_id,
                event_type=event.event_type,
                detail=event.detail,
                occurred_at=event.occurred_at,
                alert_id=alert_id,
            )
        )

    db.commit()
    return IngestResult(accepted=len(body.events), alerts_created=alerts_created)


@router.get("/sources/health", response_model=list[SourceHealthOut])
def sources_health(
    _user: User = Depends(ANALYST_OR_ADMIN),
    db: Session = Depends(get_db),
) -> list[SourceHealthOut]:
    """Last-check-in status for the registered endpoints — the Wazuh/Suricata source-health
    equivalent for a two-endpoint, agent-based deployment."""
    rows = db.scalars(select(Endpoint).order_by(Endpoint.hostname)).all()
    now = datetime.now(timezone.utc)
    out: list[SourceHealthOut] = []
    for row in rows:
        if not row.is_active:
            status = "disabled"
        elif row.last_seen_at is None:
            status = "never_seen"
        elif now - row.last_seen_at > STALE_AFTER:
            status = "stale"
        else:
            status = "online"
        out.append(
            SourceHealthOut(
                hostname=row.hostname,
                os=row.os,
                is_active=row.is_active,
                last_seen_at=row.last_seen_at,
                status=status,
            )
        )
    return out
