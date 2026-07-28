-- Materiality is analyst-declared, never inferred from severity or loss estimates.
-- Material binary assessments require matching evidence from a second distinct analyst
-- before triage/labels.py projects them into the classifier's binary label store.
ALTER TABLE triage_assessment
    ADD COLUMN material INTEGER NOT NULL DEFAULT 0 CHECK (material IN (0, 1));

CREATE INDEX idx_triage_assessment_material
    ON triage_assessment (material, finding_id, analyst);
