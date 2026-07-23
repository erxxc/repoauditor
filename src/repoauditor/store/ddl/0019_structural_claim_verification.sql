-- Scope certificate statuses explicitly and bind new claims to an immutable snapshot.
ALTER TABLE security_claim ADD COLUMN snapshot_commit TEXT;

DROP INDEX idx_claim_verification_claim;
ALTER TABLE claim_verification RENAME TO claim_verification_legacy;

CREATE TABLE claim_verification (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    claim_id            INTEGER NOT NULL REFERENCES security_claim(id) ON DELETE CASCADE,
    status              TEXT NOT NULL CHECK (
        status IN (
            'structurally_verified',
            'structurally_refuted',
            'verification_incomplete',
            'unsupported'
        )
    ),
    verifier_name       TEXT NOT NULL,
    verifier_version    TEXT NOT NULL,
    checks              TEXT NOT NULL DEFAULT '{}',
    reason              TEXT NOT NULL,
    created_at          TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (claim_id, verifier_name, verifier_version)
);

INSERT INTO claim_verification (
    id, claim_id, status, verifier_name, verifier_version, checks, reason, created_at
)
SELECT
    id,
    claim_id,
    CASE status
        -- The legacy checker consumed the producer's evidence object and was not bound
        -- to a snapshot commit. Do not retroactively award the stronger scoped statuses.
        WHEN 'verified' THEN 'verification_incomplete'
        WHEN 'refuted' THEN 'verification_incomplete'
        WHEN 'incomplete' THEN 'verification_incomplete'
        ELSE 'unsupported'
    END,
    verifier_name,
    verifier_version,
    checks,
    reason,
    created_at
FROM claim_verification_legacy;

DROP TABLE claim_verification_legacy;
CREATE INDEX idx_claim_verification_claim ON claim_verification (claim_id);
