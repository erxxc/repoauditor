-- Preserve exact direct Python caller syntax in the structured certificate.
-- Legacy claims remain valid with no caller evidence and make no caller claim.
ALTER TABLE security_claim
    ADD COLUMN caller_evidence TEXT NOT NULL DEFAULT '[]';
