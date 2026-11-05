"""Initial immutable schema, independent of future ORM model changes."""

from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None


def upgrade():
    op.create_table(
        "investigations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("raw_email", sa.Text(), nullable=False),
        sa.Column("original_base64", sa.Text(), nullable=False),
        sa.Column("evidence_sha256", sa.String(64), nullable=False),
        sa.Column("simulation", sa.Boolean(), nullable=False),
        sa.Column("sample_id", sa.String(40), nullable=True),
        sa.Column("notes", sa.Text(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
    )
    op.create_table(
        "analysis_revisions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "investigation_id",
            sa.String(36),
            sa.ForeignKey("investigations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
    )
    op.create_index(
        "ix_analysis_revisions_investigation_id",
        "analysis_revisions",
        ["investigation_id"],
    )
    op.create_table(
        "indicators",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "investigation_id",
            sa.String(36),
            sa.ForeignKey("investigations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "revision_id",
            sa.String(36),
            sa.ForeignKey("analysis_revisions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("type", sa.String(20), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=False),
    )
    for column in ["investigation_id", "revision_id", "type"]:
        op.create_index(f"ix_indicators_{column}", "indicators", [column])
    op.create_table(
        "intelligence",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "investigation_id",
            sa.String(36),
            sa.ForeignKey("investigations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("provider", sa.String(30), nullable=False),
        sa.Column("indicator", sa.Text(), nullable=False),
        sa.Column("checked_at", sa.String(40), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
    )
    op.create_index(
        "ix_intelligence_investigation_id", "intelligence", ["investigation_id"]
    )
    op.create_table(
        "report_exports",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "investigation_id",
            sa.String(36),
            sa.ForeignKey("investigations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "revision_id",
            sa.String(36),
            sa.ForeignKey("analysis_revisions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("format", sa.String(10), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
    )
    op.create_index(
        "ix_report_exports_investigation_id", "report_exports", ["investigation_id"]
    )
    op.create_table(
        "settings",
        sa.Column("key", sa.String(80), primary_key=True),
        sa.Column("value", sa.JSON(), nullable=False),
    )


def downgrade():
    for table in [
        "settings",
        "report_exports",
        "intelligence",
        "indicators",
        "analysis_revisions",
        "investigations",
    ]:
        op.drop_table(table)
