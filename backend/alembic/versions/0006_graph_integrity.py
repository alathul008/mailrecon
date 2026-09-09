from alembic import op
import sqlalchemy as sa

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def _load_duplicates(bind, table, identity_columns):
    rows = bind.execute(sa.text(f"SELECT * FROM {table} ORDER BY id")).mappings().all()
    groups = {}
    for row in rows:
        key = tuple(row[column] for column in identity_columns)
        groups.setdefault(key, []).append(row)
    return [group for group in groups.values() if len(group) > 1]


def _cleanup_exact_graph_duplicates(bind):
    node_groups = _load_duplicates(bind, "graph_nodes", ("investigation_id", "node_key"))
    for group in node_groups:
        canonical = group[0]
        comparable = [(row["node_type"], row["label"], row["node_metadata"]) for row in group]
        if any(value != comparable[0] for value in comparable[1:]):
            raise RuntimeError(
                "Ambiguous graph node duplicate detected for "
                f"investigation_id={canonical['investigation_id']} node_key={canonical['node_key']!r}; "
                "rows differ semantically and require explicit operator review."
            )
        duplicate_ids = [row["id"] for row in group[1:]]
        bind.execute(
            sa.text("DELETE FROM graph_nodes WHERE id IN :ids").bindparams(sa.bindparam("ids", expanding=True)),
            {"ids": duplicate_ids},
        )

    edge_groups = _load_duplicates(bind, "graph_edges", ("investigation_id", "source", "target", "relation"))
    for group in edge_groups:
        canonical = group[0]
        comparable = [row["confidence"] for row in group]
        if any(value != comparable[0] for value in comparable[1:]):
            raise RuntimeError(
                "Ambiguous graph edge duplicate detected for "
                f"investigation_id={canonical['investigation_id']} source={canonical['source']!r} "
                f"target={canonical['target']!r} relation={canonical['relation']!r}; "
                "rows differ in confidence and require explicit operator review."
            )
        duplicate_ids = [row["id"] for row in group[1:]]
        bind.execute(
            sa.text("DELETE FROM graph_edges WHERE id IN :ids").bindparams(sa.bindparam("ids", expanding=True)),
            {"ids": duplicate_ids},
        )


def upgrade():
    bind = op.get_bind()
    _cleanup_exact_graph_duplicates(bind)
    with op.batch_alter_table("graph_nodes") as batch:
        batch.create_unique_constraint(
            "uq_graph_nodes_investigation_node_key",
            ["investigation_id", "node_key"],
        )
    with op.batch_alter_table("graph_edges") as batch:
        batch.create_unique_constraint(
            "uq_graph_edges_investigation_identity",
            ["investigation_id", "source", "target", "relation"],
        )


def downgrade():
    with op.batch_alter_table("graph_edges") as batch:
        batch.drop_constraint("uq_graph_edges_investigation_identity", type_="unique")
    with op.batch_alter_table("graph_nodes") as batch:
        batch.drop_constraint("uq_graph_nodes_investigation_node_key", type_="unique")
