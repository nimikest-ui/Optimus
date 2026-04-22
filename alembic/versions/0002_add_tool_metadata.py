"""Add tool_metadata table for execution/parsing rules

Revision ID: 0002
Revises: 0001
Create Date: 2026-04-22 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create tool_metadata table."""
    op.create_table(
        "tool_metadata",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tool_name", sa.Text, unique=True, nullable=False),
        sa.Column("execution_type", sa.Text, default="one-shot"),
        sa.Column("timeout_seconds", sa.Integer),  # null = no timeout
        sa.Column("input_method", sa.Text, default="argv"),
        sa.Column("output_method", sa.Text, default="stdout"),
        sa.Column("output_files_pattern", sa.Text),  # regex pattern for file matching
        sa.Column("success_patterns", sa.Text),  # JSON array
        sa.Column("failure_patterns", sa.Text),  # JSON array
        sa.Column("parser_type", sa.Text, default="regex"),
        sa.Column("parser_config", sa.Text),  # JSON object with parser-specific rules
        sa.Column("requires_elevated", sa.Boolean, default=False),
        sa.Column("last_updated", sa.DateTime, default=sa.func.current_timestamp()),
    )

    op.create_index("idx_tool_name_metadata", "tool_metadata", ["tool_name"])


def downgrade() -> None:
    """Drop tool_metadata table."""
    op.drop_table("tool_metadata")
