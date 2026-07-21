-- Migration 0005 — review checkpoint + debate trail + falsification iteration trace.
--
-- Review (human-in-the-loop, maker-checker control): a finding the pipeline cannot
-- resolve (unresolved from falsify/normalize, or a too-uncertain triage result) is
-- held as a review_request. It blocks that finding from any analyze-style query until
-- a review_decision releases it. Decisions are append-only — a correction is a NEW
-- row referencing the prior one (supersedes_id), never an edit, so the ruling history
-- is a full audit trail.
--
-- Debate framing (normalize/adjudicate.py): when sources disagree on severity, the
-- adjudicator now sees each source's reasoning, not just its value. The full debate
-- (positions + outcome) is persisted so the disagreement stays auditable, not just
-- the resolved severity.
--
-- Iteration trace (falsify/challenger.py): the challenger is now a bounded
-- observe-think-act-reflect loop. Each round (evidence + verdict + self-critique) is
-- logged so the reasoning trace behind a confirm/kill/unresolved is inspectable.

-- A finding held for human review. One open request per finding.
CREATE TABLE review_request (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id      TEXT    NOT NULL,
    finding_id   INTEGER NOT NULL REFERENCES finding(id),
    stage        TEXT    NOT NULL,   -- 'falsify' | 'normalize' | 'triage'
    reason       TEXT    NOT NULL,   -- why this needs a human
    evidence     TEXT    NOT NULL,   -- JSON: citation, trust boundary, stage trace
    created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE (finding_id)
);

-- A reviewer's ruling. Append-only: corrections are new rows via supersedes_id.
CREATE TABLE review_decision (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    review_request_id  INTEGER NOT NULL REFERENCES review_request(id),
    disposition        TEXT    NOT NULL,   -- 'confirm' | 'dismiss'
    reviewer           TEXT    NOT NULL,
    rationale          TEXT    NOT NULL,
    supersedes_id      INTEGER REFERENCES review_decision(id),  -- prior decision corrected
    created_at         TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Full trail of a severity-adjudication debate (positions + outcome), not just the
-- resolved value — so a reviewer can see WHY sources disagreed.
CREATE TABLE adjudication_debate (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id              TEXT    NOT NULL,
    file                 TEXT    NOT NULL,
    line_start           INTEGER NOT NULL,
    line_end             INTEGER NOT NULL,
    positions            TEXT    NOT NULL,   -- JSON: [{source_type, source_name, severity, reasoning}]
    outcome              TEXT    NOT NULL,   -- 'consensus' | 'unresolved'
    resolved_severity    TEXT,
    synthesis_rationale  TEXT,
    created_at           TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- One round of the bounded falsification loop: evidence + verdict + self-critique.
CREATE TABLE falsification_iteration (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id          INTEGER NOT NULL REFERENCES finding(id),
    iteration           INTEGER NOT NULL,   -- 1-based round number
    evidence            TEXT    NOT NULL,   -- summary of context gathered this round
    verdict_status      TEXT    NOT NULL,
    verdict_rationale   TEXT    NOT NULL,
    verdict_confidence  REAL    NOT NULL,
    critique_upholds    INTEGER NOT NULL,   -- did self-critique uphold the verdict?
    critique_note       TEXT    NOT NULL,
    committed           INTEGER NOT NULL DEFAULT 0,  -- 1 = the accepted round
    created_at          TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE (finding_id, iteration)
);

CREATE INDEX idx_review_request_finding ON review_request (finding_id);
CREATE INDEX idx_review_decision_request ON review_decision (review_request_id, id);
CREATE INDEX idx_adjudication_debate_region ON adjudication_debate (repo_id, file, line_start, line_end);
CREATE INDEX idx_falsification_iteration_finding ON falsification_iteration (finding_id, iteration);
