-- Structured, auditable security claims and narrowly scoped deterministic verification.
CREATE TABLE security_claim (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id          INTEGER NOT NULL REFERENCES finding(id),
    claim_version       TEXT NOT NULL,
    mechanism           TEXT NOT NULL,
    source_evidence     TEXT NOT NULL DEFAULT '[]',
    sink_evidence       TEXT,
    path_nodes          TEXT NOT NULL DEFAULT '[]',
    path_predicates     TEXT NOT NULL DEFAULT '[]',
    control_candidate   TEXT,
    producer_type       TEXT NOT NULL,
    producer_name       TEXT NOT NULL,
    prompt_version      TEXT,
    created_at          TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (finding_id, claim_version)
);

CREATE TABLE claim_verification (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    claim_id            INTEGER NOT NULL REFERENCES security_claim(id) ON DELETE CASCADE,
    status              TEXT NOT NULL CHECK (
        status IN ('verified', 'refuted', 'incomplete', 'unsupported')
    ),
    verifier_name       TEXT NOT NULL,
    verifier_version    TEXT NOT NULL,
    checks              TEXT NOT NULL DEFAULT '{}',
    reason              TEXT NOT NULL,
    created_at          TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (claim_id, verifier_name, verifier_version)
);

CREATE INDEX idx_security_claim_finding ON security_claim (finding_id);
CREATE INDEX idx_claim_verification_claim ON claim_verification (claim_id);
