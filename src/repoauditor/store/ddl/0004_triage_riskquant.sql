-- Migration 0004 — triage stage + risk-quantification tables.
--
-- Triage (detect -> triage -> falsify): re-ranks deterministic-tool findings by a
-- calibrated P(actionable). triage_label is the cross-engagement ground-truth store
-- the classifier learns from; rule_prior holds the per-rule Beta-Binomial cold-start
-- prior that shrinks toward observed labels.
--
-- Risk quant (analyze/risk_quant.py, FAIR-style Monte Carlo): risk_scenario maps
-- findings to a modelled loss scenario; prior_source enforces "no unsourced priors"
-- by recording provenance for every distribution parameter; simulation_run is the
-- persisted summary of one Monte Carlo run (always a range, never one number).

-- Analyst dispositions on past deterministic-tool findings (accumulates across audits).
CREATE TABLE triage_label (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement           TEXT    NOT NULL,   -- repo_id / audit id the label came from
    rule_id              TEXT    NOT NULL,   -- SAST rule that fired
    finding_fingerprint  TEXT    NOT NULL,   -- stable hash of (rule_id,file,line,snippet)
    actionable           INTEGER NOT NULL,   -- 1 = true positive, 0 = false positive
    note                 TEXT,
    created_at           TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE (engagement, finding_fingerprint)
);

-- Per-rule Beta-Binomial prior for cold-start P(actionable), shrinking toward labels.
CREATE TABLE rule_prior (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id              TEXT    NOT NULL UNIQUE,
    alpha                REAL    NOT NULL,   -- prior + observed actionable pseudo-count
    beta                 REAL    NOT NULL,   -- prior + observed non-actionable pseudo-count
    observed_actionable  INTEGER NOT NULL DEFAULT 0,
    observed_total       INTEGER NOT NULL DEFAULT 0,
    prior_source         TEXT    NOT NULL,   -- provenance of the cold-start hyperparameters
    updated_at           TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Provenance for every distribution parameter used by risk quant (no magic numbers).
CREATE TABLE prior_source (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    kind         TEXT    NOT NULL,   -- 'magnitude' | 'frequency' | 'sme_estimate'
    param_path   TEXT    NOT NULL,   -- dotted key into priors.yaml
    source       TEXT    NOT NULL,   -- citation string copied from priors.yaml
    detail       TEXT,
    created_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- A FAIR-style loss scenario: Poisson frequency x lognormal magnitude.
CREATE TABLE risk_scenario (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id           TEXT    NOT NULL,
    name              TEXT    NOT NULL,
    finding_ids       TEXT    NOT NULL,   -- JSON array of finding ids
    frequency_lambda  REAL    NOT NULL,
    magnitude_mu      REAL    NOT NULL,
    magnitude_sigma   REAL    NOT NULL,
    frequency_source  TEXT    NOT NULL,   -- prior_source.param_path
    magnitude_source  TEXT    NOT NULL,   -- prior_source.param_path
    p_actionable      REAL,               -- triage signal folded into frequency_lambda
    created_at        TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- One Monte Carlo run: trial count + loss summary (range, not a point estimate).
CREATE TABLE simulation_run (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id           TEXT    NOT NULL,
    trials            INTEGER NOT NULL,
    mean_loss         REAL    NOT NULL,
    median_loss       REAL    NOT NULL,
    p95_loss          REAL    NOT NULL,
    scenario_summary  TEXT    NOT NULL,   -- JSON: per-scenario mean/median/p95
    tornado           TEXT    NOT NULL,   -- JSON: parameter sensitivity ranking
    seed              INTEGER,
    created_at        TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Triage output annotation on an existing finding. Ranks and may suppress, but the
-- finding itself is never deleted (CLAUDE.md) — a suppressed finding keeps its row
-- here with rank + feature attribution visible.
CREATE TABLE triage_result (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id    INTEGER NOT NULL REFERENCES finding(id),
    p_actionable  REAL    NOT NULL,   -- calibrated P(actionable)
    rank          INTEGER NOT NULL,   -- 1 = most likely actionable
    suppressed    INTEGER NOT NULL DEFAULT 0,  -- demoted below the action threshold
    model_name    TEXT    NOT NULL,   -- winning model (randomforest / xgboost)
    attributions  TEXT    NOT NULL,   -- JSON: top-3 [{feature, value, contribution}]
    created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE (finding_id)
);

CREATE INDEX idx_triage_label_rule ON triage_label (rule_id);
CREATE INDEX idx_triage_result_rank ON triage_result (finding_id);
CREATE INDEX idx_risk_scenario_repo ON risk_scenario (repo_id);
CREATE INDEX idx_simulation_run_repo ON simulation_run (repo_id, id);
