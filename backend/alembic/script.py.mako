"""${message}"""
from alembic import op
import sqlalchemy as sa
${upgrades if upgrades else 'pass'}

def downgrade():
    ${downgrades if downgrades else 'pass'}
