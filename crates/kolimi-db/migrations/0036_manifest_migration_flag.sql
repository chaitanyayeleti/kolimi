-- Remember that a full legacy-manifest scan found nothing left, so the
-- janitor does not walk the fanout directory on every sweep.
ALTER TABLE maintenance_state
    ADD COLUMN legacy_manifests_migrated INTEGER NOT NULL DEFAULT 0;
