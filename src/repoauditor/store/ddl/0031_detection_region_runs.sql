-- A live detection pass is resumable at file+lens granularity. Selection is recorded so
-- bounded coverage remains auditable and completed provider work is never repeated.
CREATE TABLE detection_region_run (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id         TEXT NOT NULL,
    commit_hash     TEXT NOT NULL,
    file            TEXT NOT NULL,
    lens            TEXT NOT NULL,
    prompt_version  TEXT NOT NULL,
    selection_basis TEXT NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
    finding_count   INTEGER NOT NULL DEFAULT 0,
    started_at      TEXT NOT NULL DEFAULT (datetime('now')),
    completed_at    TEXT,
    failure_detail  TEXT,
    UNIQUE (repo_id, commit_hash, file, lens, prompt_version)
);

CREATE INDEX idx_detection_region_repo
    ON detection_region_run (repo_id, commit_hash, status, id);
