"""SQLAlchemy ORM models."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from wafpass_server.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Run(Base):
    __tablename__ = "runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project: Mapped[str] = mapped_column(Text, default="")
    branch: Mapped[str] = mapped_column(Text, default="")
    git_sha: Mapped[str] = mapped_column(Text, default="")
    triggered_by: Mapped[str] = mapped_column(Text, default="local")
    iac_framework: Mapped[str] = mapped_column(Text, default="terraform")
    score: Mapped[int] = mapped_column(Integer, default=0)
    pillar_scores: Mapped[dict] = mapped_column(JSONB, default=dict)
    findings: Mapped[list] = mapped_column(JSONB, default=list)
    path: Mapped[str] = mapped_column(Text, default="")
    controls_loaded: Mapped[int] = mapped_column(Integer, default=0)
    controls_run: Mapped[int] = mapped_column(Integer, default=0)
    detected_regions: Mapped[list] = mapped_column(JSONB, default=list)
    source_paths: Mapped[list] = mapped_column(JSONB, default=list)
    controls_meta: Mapped[list] = mapped_column(JSONB, default=list)
    plan_changes: Mapped[dict | None] = mapped_column(JSONB, nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
