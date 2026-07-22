-- Append-only score history. triage_result remains the latest-state projection used
-- by the pipeline; this table preserves every scoring pass for cohort analysis.
CREATE TABLE triage_score (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id     INTEGER NOT NULL REFERENCES finding(id),
    triage_run_id  INTEGER NOT NULL REFERENCES triage_model_run(id),
    p_actionable   REAL NOT NULL,
    rank           INTEGER NOT NULL,
    suppressed     INTEGER NOT NULL,
    scored_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_triage_score_finding ON triage_score (finding_id, id);
CREATE INDEX idx_triage_score_run ON triage_score (triage_run_id, id);
