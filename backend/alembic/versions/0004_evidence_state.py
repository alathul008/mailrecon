from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("findings", sa.Column("evidence_state", sa.String(32), nullable=True))
    op.create_index("ix_findings_evidence_state", "findings", ["evidence_state"], unique=False)


def downgrade():
    op.drop_index("ix_findings_evidence_state", table_name="findings")
    op.drop_column("findings", "evidence_state")
