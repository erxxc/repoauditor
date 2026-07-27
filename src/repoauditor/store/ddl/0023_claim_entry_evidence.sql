-- Preserve deterministic entry-point evidence in the structured certificate.
ALTER TABLE security_claim
    ADD COLUMN entry_evidence TEXT NOT NULL DEFAULT '[]';
