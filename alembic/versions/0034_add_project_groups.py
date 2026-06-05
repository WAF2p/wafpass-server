"""Add project_groups and user_groups tables for group-based access control.

Revision ID: 0034
Revises: 0033
Create Date: 2026-06-02

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


# revision identifiers, used by Alembic.
revision: str = "0034"
down_revision: Union[str, None] = "0033"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # project_groups: defines which groups can access which projects
    op.create_table(
        "project_groups",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("project", sa.Text(), nullable=False, index=True),
        sa.Column("group_name", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", UUID(as_uuid=True), nullable=True),
        sa.UniqueConstraint("project", "group_name", name="uq_project_group"),
    )

    # user_groups: tracks which groups each user belongs to (from IdP)
    op.create_table(
        "user_groups",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("group_name", sa.Text(), nullable=False),
        sa.Column("provider", sa.Text(), nullable=False, server_default="*"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("user_id", "group_name", "provider", name="uq_user_group_provider"),
    )

    # Add foreign keys
    op.create_foreign_key(
        "fk_project_groups_created_by", "project_groups", "users",
        ["created_by"], ["id"], ondelete="SET NULL"
    )
    op.create_foreign_key(
        "fk_user_groups_user_id", "user_groups", "users",
        ["user_id"], ["id"], ondelete="CASCADE"
    )


def downgrade() -> None:
    op.drop_table("user_groups")
    op.drop_table("project_groups")
