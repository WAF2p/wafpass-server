"""Fix group names that were incorrectly stored as single characters.

Revision ID: 0035
Revises: 0034
Create Date: 2026-06-03

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0035"
down_revision: Union[str, None] = "0034"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Update single-character group names to their full names
    # These were likely created by accident with only the first character
    op.execute("UPDATE project_groups SET group_name = 'c-level' WHERE group_name = 'c'")
    op.execute("UPDATE project_groups SET group_name = 'g-management' WHERE group_name = 'g'")
    op.execute("UPDATE project_groups SET group_name = 'Test' WHERE group_name = 't'")


def downgrade() -> None:
    # Revert to single characters if needed
    op.execute("UPDATE project_groups SET group_name = 'c' WHERE group_name = 'c-level'")
    op.execute("UPDATE project_groups SET group_name = 'g' WHERE group_name = 'g-management'")
    op.execute("UPDATE project_groups SET group_name = 't' WHERE group_name = 'Test'")
