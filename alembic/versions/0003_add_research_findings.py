"""Add research_findings table for storing deep research data."""

from alembic import op
import sqlalchemy as sa


revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "research_findings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("query", sa.String(), nullable=False),  # Search term: "airmon-ng"
        sa.Column("source", sa.String(), nullable=False),  # google, github, exploit-db, etc.
        sa.Column("title", sa.String(), nullable=True),  # Finding title
        sa.Column("url", sa.String(), nullable=True),  # Source URL
        sa.Column("summary", sa.Text(), nullable=True),  # Brief description
        sa.Column("cves", sa.Text(), nullable=True),  # JSON: ["CVE-2025-X", "CVE-2024-Y"]
        sa.Column("tools", sa.Text(), nullable=True),  # JSON: ["nikto", "nmap"]
        sa.Column("severity", sa.String(), nullable=True),  # critical, high, medium, low
        sa.Column(
            "found_at",
            sa.DateTime(),
            nullable=True,
            server_default=sa.func.current_timestamp(),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=True,
            server_default=sa.func.current_timestamp(),
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # Index for fast lookups by query
    op.create_index(
        "idx_research_query",
        "research_findings",
        ["query"],
    )

    # Index for CVE lookups
    op.create_index(
        "idx_research_cves",
        "research_findings",
        ["cves"],
    )


def downgrade() -> None:
    op.drop_index("idx_research_cves")
    op.drop_index("idx_research_query")
    op.drop_table("research_findings")
