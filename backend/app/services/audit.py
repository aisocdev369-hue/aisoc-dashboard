from sqlalchemy.orm import Session

from app.db.models import AuditLog


def record(
    db: Session,
    action: str,
    actor_id: int | None = None,
    target: str | None = None,
    detail: str | None = None,
    ip: str | None = None,
) -> None:
    """Append an audit entry. Never pass passwords, tokens or full prompts/responses here."""
    db.add(
        AuditLog(
            actor_id=actor_id,
            action=action[:64],
            target=target[:120] if target else None,
            detail=detail[:500] if detail else None,
            ip=ip[:45] if ip else None,
        )
    )
    db.commit()
