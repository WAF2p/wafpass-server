"""Keeps ``mandant_ancestry`` in sync with ``mandants.parent_id``.

See decisions/adrs/ADR-004-hierarchy-aware-rls.md. A closure table,
maintained by application-level recomputation rather than a database
trigger — an explicit alternative the ADR itself offers, and this
codebase's own convention (zero Postgres triggers anywhere else). Mandate
counts are small ("tens, not millions" per the ADR), so a full rebuild on
every create/reparent is simpler and easier to reason about than
incremental closure-table maintenance, and it rules out an entire class of
bug (closure table and parent_id silently disagreeing) that an incremental
or trigger-based approach could introduce.
"""
from __future__ import annotations

import uuid

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from wafpass_server.models import Mandant


async def recompute_mandant_ancestry(db: AsyncSession | AsyncConnection) -> None:
    """Rebuild ``mandant_ancestry`` from scratch from the current
    ``mandants.parent_id`` data. Call after creating a mandant, or after
    updating one whose ``parent_id`` changed.

    Every mandant gets a depth-0 self-row (``ancestor_id == descendant_id``)
    in addition to one row per ancestor — so ``SELECT descendant_id FROM
    mandant_ancestry WHERE ancestor_id = X`` already includes X itself,
    which both the RLS policy's group_admin/group_viewer branch and the
    rollup endpoint rely on.

    Accepts either an ``AsyncSession`` (the ordinary admin.py mandant CRUD
    handlers) or a bare ``AsyncConnection`` (Phase 2's activation endpoint,
    which operates on the owner connection, not an ORM session) — only
    plain-column selects and raw ``text()`` statements are used here, both
    of which run identically on either.
    """
    result = await db.execute(select(Mandant.id, Mandant.parent_id))
    parent_of: dict[uuid.UUID, uuid.UUID | None] = {row.id: row.parent_id for row in result.all()}

    rows: list[dict] = []
    for mandant_id in parent_of:
        rows.append({"ancestor_id": mandant_id, "descendant_id": mandant_id, "depth": 0})
        depth = 1
        current = parent_of.get(mandant_id)
        seen: set[uuid.UUID] = set()
        while current is not None and current not in seen:
            rows.append({"ancestor_id": current, "descendant_id": mandant_id, "depth": depth})
            seen.add(current)
            current = parent_of.get(current)
            depth += 1

    await db.execute(text("DELETE FROM mandant_ancestry"))
    if rows:
        await db.execute(
            text(
                "INSERT INTO mandant_ancestry (ancestor_id, descendant_id, depth) "
                "VALUES (:ancestor_id, :descendant_id, :depth)"
            ),
            rows,
        )
