"""issue #25: widen vm_interfaces.bridge and virtual_machines.node to TEXT

vCenter sync aborted with

    StringDataRightTruncationError: value too long for type character varying(64)

on an NSX-T generated portgroup name (78 chars, contains a UUID). The length of a
name coming from a third-party platform is not ours to bound -- for a plain
reference string there is nothing to gain from a limit and a whole sync run to
lose. Same reasoning for `node`, which holds an ESXi host FQDN (up to 253 chars).

Revision ID: 0129_virt_long_names
Revises: 0128_sftp_sort
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0129_virt_long_names"
down_revision = "0128_sftp_sort"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("vm_interfaces", "bridge",
                    existing_type=sa.String(64), type_=sa.Text(), existing_nullable=True)
    op.alter_column("virtual_machines", "node",
                    existing_type=sa.String(128), type_=sa.Text(), existing_nullable=True)


def downgrade() -> None:
    # Rows longer than the old limit would fail the cast, so truncate on the way
    # back down -- a downgrade must not leave the database unable to load.
    op.execute("UPDATE vm_interfaces SET bridge = left(bridge, 64) WHERE length(bridge) > 64")
    op.execute("UPDATE virtual_machines SET node = left(node, 128) WHERE length(node) > 128")
    op.alter_column("virtual_machines", "node",
                    existing_type=sa.Text(), type_=sa.String(128), existing_nullable=True)
    op.alter_column("vm_interfaces", "bridge",
                    existing_type=sa.Text(), type_=sa.String(64), existing_nullable=True)
