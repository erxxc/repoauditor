-- Existing scenarios keep their historical interpretation; new aggregate rows carry an
-- explicit methodology marker and are never confused with per-finding simulations.
ALTER TABLE risk_scenario
    ADD COLUMN methodology_version TEXT NOT NULL DEFAULT 'legacy_per_finding_v1';
