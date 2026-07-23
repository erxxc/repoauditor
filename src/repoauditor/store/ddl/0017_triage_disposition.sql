-- Additive analyst ground-truth taxonomy. Historical assessments remain valid with NULL.
ALTER TABLE triage_assessment ADD COLUMN disposition TEXT
    CHECK (
        disposition IS NULL OR disposition IN (
            'confirmed_actionable',
            'tool_incorrect',
            'unreachable',
            'not_attacker_controlled',
            'mitigated',
            'duplicate',
            'valid_not_actionable',
            'insufficient_evidence'
        )
    );

CREATE INDEX idx_triage_assessment_disposition
    ON triage_assessment (disposition, engagement);
