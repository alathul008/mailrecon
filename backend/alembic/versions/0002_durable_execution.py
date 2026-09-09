from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("investigations", sa.Column("execution_token", sa.String(64), nullable=True))
    op.add_column("investigations", sa.Column("execution_started_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("investigations", sa.Column("execution_heartbeat_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_investigations_execution_token", "investigations", ["execution_token"])
    op.create_index("ix_investigations_execution_heartbeat_at", "investigations", ["execution_heartbeat_at"])


def downgrade():
    op.drop_index("ix_investigations_execution_heartbeat_at", table_name="investigations")
    op.drop_index("ix_investigations_execution_token", table_name="investigations")
    op.drop_column("investigations", "execution_heartbeat_at")
    op.drop_column("investigations", "execution_started_at")
    op.drop_column("investigations", "execution_token")
