-- Durable provenance for each triage scoring pass and score/label timestamps.
CREATE TABLE triage_model_run (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id               TEXT NOT NULL,
    model_name            TEXT NOT NULL,
    model_version         TEXT NOT NULL,
    feature_schema_version TEXT NOT NULL,
    training_label_count  INTEGER NOT NULL,
    evaluation_label_count INTEGER NOT NULL,
    label_source_counts   TEXT NOT NULL,
    synthetic_share       REAL NOT NULL,
    synthetic_dropped     INTEGER NOT NULL,
    calibration           TEXT NOT NULL,
    evaluation_basis      TEXT NOT NULL,
    split_strategy        TEXT NOT NULL,
    split_detail          TEXT NOT NULL,
    evaluations           TEXT NOT NULL,
    scanner_versions      TEXT NOT NULL,
    created_at            TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_triage_model_run_repo ON triage_model_run (repo_id, id);

ALTER TABLE triage_result
    ADD COLUMN triage_run_id INTEGER REFERENCES triage_model_run(id);
ALTER TABLE triage_result ADD COLUMN scored_at TEXT;
ALTER TABLE triage_label ADD COLUMN updated_at TEXT;
