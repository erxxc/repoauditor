-- Preserve exact Flask blueprint-registration syntax tied to a local route subject.
-- This does not assert that application startup executes or that the route is reachable.
ALTER TABLE security_claim
    ADD COLUMN registration_evidence TEXT NOT NULL DEFAULT '[]';
