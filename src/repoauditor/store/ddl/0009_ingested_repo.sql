-- Repository ingest inventory used by `repoauditor repos list`.
CREATE TABLE ingested_repo (
    repo_id       TEXT NOT NULL,
    source        TEXT NOT NULL,
    commit_hash   TEXT NOT NULL,
    ingested_at   TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (repo_id, commit_hash)
);

CREATE INDEX idx_ingested_repo_latest ON ingested_repo (repo_id, ingested_at DESC);
