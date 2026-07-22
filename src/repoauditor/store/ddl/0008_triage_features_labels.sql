-- Migration 0008 — real TriageLabel training loop support.
--
-- Turns triage's synthetic-only training into a closed learning loop that accumulates
-- *real* labels across engagements. Two additions:
--
--   triage_features    Persists the exact feature vector (and its column order) computed
--                      for each deterministic-tool finding at triage time. This is the
--                      bridge that lets an accumulated triage_label (keyed by rule +
--                      fingerprint) be joined back to the numeric features the classifier
--                      trains on — cross-engagement, since the row carries the engagement.
--                      Without it a label is just a disposition with no features to learn
--                      from; with it, real labels become real training rows.
--
--   triage_label.source  Records how a label was obtained: 'manual' (an analyst asserted
--                      it via `repoauditor triage-label`) or 'derived_falsify' /
--                      'derived_review' (harvested from a downstream falsify verdict or
--                      human review decision). Manual labels take precedence — the
--                      derivation pass never overwrites a 'manual' row (enforced by the
--                      `WHERE source != 'manual'` guard in db.upsert_triage_label). Legacy
--                      rows default to 'manual' (a directly-asserted label is ground truth).

ALTER TABLE triage_label ADD COLUMN source TEXT NOT NULL DEFAULT 'manual';

-- The exact triaged feature vector for a finding — the join bridge to triage_label.
CREATE TABLE triage_features (
    finding_id     INTEGER PRIMARY KEY REFERENCES finding(id),
    engagement     TEXT    NOT NULL,   -- repo_id the features were computed on
    rule_id        TEXT    NOT NULL,   -- SAST rule that fired (label key)
    fingerprint    TEXT    NOT NULL,   -- (rule,file,line,snippet) hash == triage_label.finding_fingerprint
    features       TEXT    NOT NULL,   -- JSON array of floats; order == feature_names
    feature_names  TEXT    NOT NULL,   -- JSON array; guards against FEATURE_NAMES drift
    created_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Join key for turning accumulated labels into training rows (engagement + fingerprint).
CREATE INDEX idx_triage_features_join ON triage_features (engagement, fingerprint);
