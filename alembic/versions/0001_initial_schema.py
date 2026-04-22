"""Initial schema: kali_tools and pentest databases

Revision ID: 0001
Revises: None
Create Date: 2026-04-22 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create initial schema."""
    # kali_tools table
    op.create_table(
        "kali_tools",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tool_name", sa.Text, unique=True, nullable=False),
        sa.Column("category", sa.Text),
        sa.Column("attack_phase", sa.Text),
        sa.Column("one_line_desc", sa.Text),
        sa.Column("syntax_template", sa.Text),
        sa.Column("man_page_compressed", sa.Text),
        sa.Column("tags", sa.Text),
        sa.Column("tier", sa.Integer, default=1),
        sa.Column("pkg_name", sa.Text),
        sa.Column("installed", sa.Boolean, default=True),
        sa.Column("success_rate", sa.Float, default=0.5),
        sa.Column("use_count", sa.Integer, default=0),
        sa.Column("embedding", sa.BLOB),
        sa.Column("last_updated", sa.DateTime, default=sa.func.current_timestamp()),
    )
    op.create_index("idx_attack_phase", "kali_tools", ["attack_phase"])

    # Create FTS5 virtual table for kali_tools
    op.execute(
        """
        CREATE VIRTUAL TABLE kali_tools_fts USING fts5(
            tool_name, tags, one_line_desc, man_page_compressed,
            content='kali_tools', content_rowid='id'
        );
        """
    )

    # sessions table
    op.create_table(
        "sessions",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("project_id", sa.Text),
        sa.Column("playbook", sa.Text),
        sa.Column("target", sa.Text),
        sa.Column("tier", sa.Integer),
        sa.Column("started_at", sa.DateTime, default=sa.func.current_timestamp()),
        sa.Column("finished_at", sa.DateTime),
        sa.Column("outcome", sa.Text),
    )

    # steps table
    op.create_table(
        "steps",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("session_id", sa.Integer, sa.ForeignKey("sessions.id")),
        sa.Column("step_num", sa.Integer),
        sa.Column("goal", sa.Text),
        sa.Column("tool_used", sa.Text),
        sa.Column("args", sa.Text),
        sa.Column("raw_output", sa.Text),
        sa.Column("parsed_output", sa.Text),
        sa.Column("outcome", sa.Text),
        sa.Column("attempt_count", sa.Integer, default=1),
    )

    # vulnerabilities table
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("session_id", sa.Integer, sa.ForeignKey("sessions.id")),
        sa.Column("cve_id", sa.Text),
        sa.Column("tool_used", sa.Text),
        sa.Column("severity", sa.Text),
        sa.Column("attack_technique", sa.Text),
        sa.Column("loot", sa.Text),
    )


def downgrade() -> None:
    """Drop all tables."""
    op.drop_table("vulnerabilities")
    op.drop_table("steps")
    op.drop_table("sessions")
    op.execute("DROP TABLE IF EXISTS kali_tools_fts")
    op.drop_table("kali_tools")
