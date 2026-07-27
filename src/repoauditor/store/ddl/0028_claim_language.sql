-- Bind each structural certificate to the language-specific trusted checker.
-- Legacy certificates were produced by the Python-only implementation.
ALTER TABLE security_claim
    ADD COLUMN language TEXT NOT NULL DEFAULT 'python';
