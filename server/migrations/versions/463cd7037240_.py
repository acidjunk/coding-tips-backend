"""empty message

Revision ID: 463cd7037240
Revises: 
Create Date: 2018-02-24 13:14:18.602635

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '463cd7037240'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('coding_categories',
    sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_coding_categories_id'), 'coding_categories', ['id'], unique=False)
    op.create_index(op.f('ix_coding_categories_name'), 'coding_categories', ['name'], unique=True)
    op.create_table('coding_tips',
    sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=True),
    sa.Column('content', sa.Text(), nullable=True),
    sa.Column('active', sa.Boolean(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_coding_tips_id'), 'coding_tips', ['id'], unique=False)
    op.create_index(op.f('ix_coding_tips_name'), 'coding_tips', ['name'], unique=True)
    op.create_table('roles',
    sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('name', sa.String(length=80), nullable=True),
    sa.Column('description', sa.String(length=255), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_index(op.f('ix_roles_id'), 'roles', ['id'], unique=False)
    op.create_table('users',
    sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('email', sa.String(length=255), nullable=True),
    sa.Column('username', sa.String(length=255), nullable=True),
    sa.Column('password', sa.String(length=255), nullable=True),
    sa.Column('active', sa.Boolean(), nullable=True),
    sa.Column('confirmed_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('username')
    )
    op.create_index(op.f('ix_users_id'), 'users', ['id'], unique=False)
    op.create_table('coding_categories_to_coding_tips',
    sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('coding_category_id', postgresql.UUID(as_uuid=True), nullable=True),
    sa.Column('coding_tip_id', postgresql.UUID(as_uuid=True), nullable=True),
    sa.ForeignKeyConstraint(['coding_category_id'], ['coding_categories.id'], ),
    sa.ForeignKeyConstraint(['coding_tip_id'], ['coding_tips.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_coding_categories_to_coding_tips_id'), 'coding_categories_to_coding_tips', ['id'], unique=False)
    op.create_table('roles_to_users',
    sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True),
    sa.Column('role_id', postgresql.UUID(as_uuid=True), nullable=True),
    sa.ForeignKeyConstraint(['role_id'], ['roles.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_roles_to_users_id'), 'roles_to_users', ['id'], unique=False)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_roles_to_users_id'), table_name='roles_to_users')
    op.drop_table('roles_to_users')
    op.drop_index(op.f('ix_coding_categories_to_coding_tips_id'), table_name='coding_categories_to_coding_tips')
    op.drop_table('coding_categories_to_coding_tips')
    op.drop_index(op.f('ix_users_id'), table_name='users')
    op.drop_table('users')
    op.drop_index(op.f('ix_roles_id'), table_name='roles')
    op.drop_table('roles')
    op.drop_index(op.f('ix_coding_tips_name'), table_name='coding_tips')
    op.drop_index(op.f('ix_coding_tips_id'), table_name='coding_tips')
    op.drop_table('coding_tips')
    op.drop_index(op.f('ix_coding_categories_name'), table_name='coding_categories')
    op.drop_index(op.f('ix_coding_categories_id'), table_name='coding_categories')
    op.drop_table('coding_categories')
    # ### end Alembic commands ###
