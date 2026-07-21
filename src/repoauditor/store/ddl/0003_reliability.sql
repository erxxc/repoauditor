-- Migration 0003 — reliability layer tables.
--
-- validation_failure: the structured-output trail. Every exhausted parse/validation
-- retry from llm/client.py lands here, so invalid model output is impossible to miss.
-- eval_run: one row per golden-harness execution, for closed-loop regression gating.

CREATE TABLE validation_failure (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    module            TEXT    NOT NULL,   -- calling stage (map / detect / falsify / normalize)
    prompt_version    TEXT    NOT NULL,
    raw_response      TEXT    NOT NULL,   -- truncated
    validation_error  TEXT    NOT NULL,
    created_at        TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE eval_run (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    lineage               TEXT    NOT NULL,   -- groups comparable runs (corpus/fixture id)
    prompt_versions       TEXT    NOT NULL,   -- JSON: {stage: prompt_version}
    precision             REAL    NOT NULL,
    recall                REAL    NOT NULL,
    regressed_from_prior  INTEGER NOT NULL DEFAULT 0,
    created_at            TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_validation_failure_module ON validation_failure (module);
CREATE INDEX idx_eval_run_lineage ON eval_run (lineage, id);
