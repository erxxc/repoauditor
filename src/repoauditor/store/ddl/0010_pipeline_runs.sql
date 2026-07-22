CREATE TABLE pipeline_run (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    source         TEXT NOT NULL,
    repo_id        TEXT,
    commit_hash    TEXT,
    status         TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
    started_at     TEXT NOT NULL DEFAULT (datetime('now')),
    completed_at   TEXT,
    failed_stage   TEXT,
    failure_detail TEXT,
    artifacts      TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX idx_pipeline_run_source_latest
    ON pipeline_run (source, started_at DESC, id DESC);
CREATE INDEX idx_pipeline_run_repo_latest
    ON pipeline_run (repo_id, started_at DESC, id DESC);

CREATE TABLE stage_run (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    pipeline_run_id INTEGER NOT NULL REFERENCES pipeline_run(id) ON DELETE CASCADE,
    stage           TEXT NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
    started_at      TEXT NOT NULL DEFAULT (datetime('now')),
    completed_at    TEXT,
    summary         TEXT NOT NULL DEFAULT '{}',
    artifacts       TEXT NOT NULL DEFAULT '[]',
    failure_detail  TEXT,
    UNIQUE (pipeline_run_id, stage)
);

CREATE INDEX idx_stage_run_pipeline ON stage_run (pipeline_run_id, id);
