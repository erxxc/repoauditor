-- Migration 0007 — analyze-stage schema additions (corroboration scoring + deal risk).
--
-- Applied-once and immutable: never edit this file after it has been applied.
--
-- 1. Corroboration gains a calibrated agreement `score` and a `match_basis` string, so
--    the analyze/corroboration pass can persist *why* two sources were judged to flag the
--    same underlying issue and how strong that agreement is (independence-weighted). Both
--    are NULLABLE: rows written by normalize/adjudicate.py before analyze runs — and any
--    pre-0007 rows — remain valid with NULL score/basis. Adding nullable columns needs no
--    table rebuild (unlike a CHECK change), so a plain ALTER TABLE ADD COLUMN is safe here.
--
-- 2. deal_risk is a sidecar annotation on a finding (same discipline as triage_result): a
--    deal-relevant weight layered *alongside* technical severity, never overwriting it. The
--    four component sub-scores are persisted so `weight` is fully reconstructable (no magic
--    numbers). UNIQUE(finding_id) makes the write idempotent per finding.

ALTER TABLE corroboration ADD COLUMN score REAL;
ALTER TABLE corroboration ADD COLUMN match_basis TEXT;

CREATE TABLE deal_risk (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id             INTEGER NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
    weight                 REAL    NOT NULL,   -- deal-relevant weight in [0,1]
    band                   TEXT    NOT NULL,   -- low | elevated | high | critical
    production_exposure    TEXT    NOT NULL,   -- direct | indirect | internal | unknown
    remediation_category   TEXT    NOT NULL,   -- fast | moderate | major | redesign
    rep_warranty_category  TEXT,               -- matched R&W category, if any
    rep_warranty_relevant  INTEGER NOT NULL DEFAULT 0,  -- 1 = under a standard security rep
    severity_component     REAL    NOT NULL,
    exposure_component     REAL    NOT NULL,
    remediation_component  REAL    NOT NULL,
    rep_warranty_component REAL    NOT NULL,
    rationale              TEXT    NOT NULL,
    created_at             TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE (finding_id),
    CHECK (weight >= 0.0 AND weight <= 1.0)
);

CREATE INDEX idx_deal_risk_finding ON deal_risk (finding_id);
