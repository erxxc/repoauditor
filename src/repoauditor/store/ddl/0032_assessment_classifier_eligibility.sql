-- Human evidence applies to every canonical finding. Only findings with the declared
-- triage feature schema may project into classifier labels/training.
ALTER TABLE triage_assessment
    ADD COLUMN classifier_eligible INTEGER NOT NULL DEFAULT 1
    CHECK (classifier_eligible IN (0, 1));

CREATE INDEX idx_triage_assessment_classifier_eligible
    ON triage_assessment (classifier_eligible, engagement, finding_id);
