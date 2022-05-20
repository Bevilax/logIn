"""empty message

Revision ID: 94a8345b4c17
Revises: ef8bf8727b10
Create Date: 2022-05-20 00:41:55.932045

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '94a8345b4c17'
down_revision = 'ef8bf8727b10'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('password', sa.String(length=300), nullable=False))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('user', 'password')
    # ### end Alembic commands ###