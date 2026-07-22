-- Append-only analyst assessments support controlled label collection and abstention.
-- Binary outcomes also update triage_label as the effective training-label projection.
CREATE TABLE triage_assessment (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  INTEGER NOT NULL REFERENCES finding(id),
    engagement  TEXT NOT NULL,
    outcome     TEXT NOT NULL CHECK (outcome IN ('true_positive', 'false_positive', 'uncertain')),
    rationale   TEXT NOT NULL,
    analyst     TEXT NOT NULL,
    dimensions  TEXT NOT NULL DEFAULT '[]',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_triage_assessment_finding ON triage_assessment (finding_id, id);
CREATE INDEX idx_triage_assessment_engagement ON triage_assessment (engagement, id);
