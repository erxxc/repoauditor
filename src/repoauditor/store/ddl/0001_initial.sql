-- Migration 0001 — initial schema.
--
-- Applied-once and immutable: never edit this file after it has been applied.
-- Schema changes ship as a new numbered migration (0002_*.sql, ...).
--
-- Tables: trust_boundary, entity (map-stage output) and finding, corroboration
-- (detect/falsify/normalize output). Findings foreign-key to a trust boundary so
-- every finding traces back to why it matters architecturally.

CREATE TABLE trust_boundary (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id      TEXT    NOT NULL,
    name         TEXT    NOT NULL,
    description  TEXT,
    created_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Generic architectural entity produced by the map stage. `kind` discriminates
-- entry points, data stores, external integrations and internal components.
CREATE TABLE entity (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id            TEXT    NOT NULL,
    kind               TEXT    NOT NULL,
    name               TEXT    NOT NULL,
    location           TEXT,
    trust_boundary_id  INTEGER REFERENCES trust_boundary(id) ON DELETE SET NULL,
    metadata           TEXT,   -- JSON blob
    created_at         TEXT    NOT NULL DEFAULT (datetime('now')),
    CHECK (kind IN ('entry_point', 'data_store', 'integration', 'component'))
);

-- Atomic unit of the pipeline. A finding always carries its citation
-- (file/line_range/citation_snippet) and its origin (a lens OR a tool).
CREATE TABLE finding (
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
    -- Every finding originates from at least one lens or tool.
    CHECK (source_lens IS NOT NULL OR source_tool IS NOT NULL),
    CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    CHECK (falsification_status IN ('confirmed', 'killed', 'unresolved')),
    CHECK (confidence >= 0.0 AND confidence <= 1.0),
    CHECK (line_end >= line_start)
);

-- Independent corroboration of a finding by another lens/tool. Corroboration is
-- the only evidence (besides a confirming falsification pass) that licenses a
-- severity upgrade.
CREATE TABLE corroboration (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id   INTEGER NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
    source_type  TEXT    NOT NULL,
    source_name  TEXT    NOT NULL,
    note         TEXT,
    created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    CHECK (source_type IN ('lens', 'tool')),
    UNIQUE (finding_id, source_type, source_name)
);

CREATE INDEX idx_finding_repo         ON finding (repo_id);
CREATE INDEX idx_finding_trust_boundary ON finding (trust_boundary_id);
CREATE INDEX idx_entity_repo          ON entity (repo_id);
CREATE INDEX idx_corroboration_finding ON corroboration (finding_id);
