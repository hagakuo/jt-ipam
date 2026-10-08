"""Merge the deployed NKUST refresh-token branch with upstream v1.0.1."""

revision = "0188_merge_local_refresh"
down_revision = ("0115_merge_local_refresh", "0187_change_impact")
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
