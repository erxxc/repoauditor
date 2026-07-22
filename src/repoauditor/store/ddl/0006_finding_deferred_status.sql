-- Widen finding.falsification_status to admit 'deferred' (a candidate outside this
-- falsify run's LLM budget — not yet examined, to be resumed by a later run).
--
-- SQLite cannot ALTER a CHECK constraint in place, so the finding table is rebuilt.
-- The migration runner applies each file via executescript(), which COMMITs first and
-- then runs in autocommit — so `PRAGMA foreign_keys` takes effect here. We disable FK
-- enforcement for the swap so DROP TABLE finding does not cascade-delete child rows
-- (corroboration is ON DELETE CASCADE) and re-enable it after. Child tables reference
-- `finding` by name, so renaming finding_new -> finding restores their links.

PRAGMA foreign_keys=OFF;

CREATE TABLE finding_new (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id               TEXT    NOT NULL,
    title                 TEXT    NOT NULL,
    file                  TEXT    NOT NULL,
    line_start            INTEGER NOT NULL,
    line_end              INTEGER NOT NULL,
    citation_snippet      TEXT    NOT NULL,
    source_lens           TEXT,
    source_tool           TEXT,
    confidence            REAL    NOT NULL,
    severity              TEXT    NOT NULL,
    falsification_status  TEXT    NOT NULL DEFAULT 'unresolved',
    trust_boundary_id     INTEGER REFERENCES trust_boundary(id) ON DELETE SET NULL,
    entity_id             INTEGER REFERENCES entity(id) ON DELETE SET NULL,
    description           TEXT,
    created_at            TEXT    NOT NULL DEFAULT (datetime('now')),
    falsification_reason  TEXT,
    CHECK (source_lens IS NOT NULL OR source_tool IS NOT NULL),
    CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    CHECK (falsification_status IN ('confirmed', 'killed', 'unresolved', 'deferred')),
    CHECK (confidence >= 0.0 AND confidence <= 1.0),
    CHECK (line_end >= line_start)
);

INSERT INTO finding_new (
    id, repo_id, title, file, line_start, line_end, citation_snippet,
    source_lens, source_tool, confidence, severity, falsification_status,
    trust_boundary_id, entity_id, description, created_at, falsification_reason
)
SELECT
    id, repo_id, title, file, line_start, line_end, citation_snippet,
    source_lens, source_tool, confidence, severity, falsification_status,
    trust_boundary_id, entity_id, description, created_at, falsification_reason
FROM finding;

DROP TABLE finding;
ALTER TABLE finding_new RENAME TO finding;

CREATE INDEX idx_finding_repo           ON finding (repo_id);
CREATE INDEX idx_finding_trust_boundary ON finding (trust_boundary_id);

PRAGMA foreign_keys=ON;
