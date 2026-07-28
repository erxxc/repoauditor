-- Persist the concrete witness and small-checker result used to support a
-- security-control bypass claim. JSON keeps the iteration trace self-contained while
-- the typed validation remains in falsify/counterexample.py.
ALTER TABLE falsification_iteration
    ADD COLUMN counterexample_witness TEXT;

ALTER TABLE falsification_iteration
    ADD COLUMN counterexample_verification TEXT;
