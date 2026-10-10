CREATE TABLE dead_props (
    node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    namespace TEXT NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (node_id, namespace, name)
) WITHOUT ROWID;
