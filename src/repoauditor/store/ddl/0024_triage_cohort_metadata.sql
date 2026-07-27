-- Persist explicit detector/language metadata beside each triaged feature row.
--
-- Detector is sourced from SARIF run.tool.driver.name. Language is accepted only from
-- SARIF artifact.sourceLanguage; it is never inferred from rule ids or file extensions.
-- Legacy and unavailable values fail closed to "unknown" with unavailable provenance.

ALTER TABLE triage_features ADD COLUMN detector TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE triage_features ADD COLUMN detector_source TEXT NOT NULL DEFAULT 'unavailable';
ALTER TABLE triage_features ADD COLUMN language TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE triage_features ADD COLUMN language_source TEXT NOT NULL DEFAULT 'unavailable';
