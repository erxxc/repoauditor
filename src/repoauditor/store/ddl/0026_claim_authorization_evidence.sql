-- Preserve same-function Python authorization-candidate syntax in the certificate.
-- This is identity/location evidence only; it does not assert control effectiveness.
ALTER TABLE security_claim
    ADD COLUMN authorization_evidence TEXT NOT NULL DEFAULT '[]';
