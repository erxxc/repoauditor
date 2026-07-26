-- Detector-supplied natural identity for findings whose display location is not unique.
-- SCA advisories use ecosystem/package/version/advisory-id; nullable preserves all
-- existing lens and deterministic findings without inventing an identity for them.
ALTER TABLE finding ADD COLUMN identity_key TEXT;

CREATE INDEX idx_finding_identity ON finding (repo_id, identity_key);
