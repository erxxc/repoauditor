-- Preserve historical records, but distinguish their unverifiable citation strings from
-- the exact provenance required for every newly-created PriorSource.
ALTER TABLE prior_source ADD COLUMN publication TEXT;
ALTER TABLE prior_source ADD COLUMN edition TEXT;
ALTER TABLE prior_source ADD COLUMN locator TEXT;
ALTER TABLE prior_source ADD COLUMN url TEXT;
ALTER TABLE prior_source ADD COLUMN transformation TEXT;
ALTER TABLE prior_source ADD COLUMN provenance_status TEXT NOT NULL DEFAULT 'legacy_unverified';

-- Explicit two-layer scenario state. The pre-existing frequency_lambda/p_actionable
-- columns remain readable for historical runs; new simulations use the arrays below.
ALTER TABLE risk_scenario ADD COLUMN validity_probabilities TEXT NOT NULL DEFAULT '[]';
ALTER TABLE risk_scenario ADD COLUMN validity_sources TEXT NOT NULL DEFAULT '[]';
ALTER TABLE risk_scenario ADD COLUMN conditional_frequency_lambdas TEXT NOT NULL DEFAULT '[]';
ALTER TABLE risk_scenario ADD COLUMN conditional_frequency_source TEXT;
ALTER TABLE risk_scenario ADD COLUMN threat_signal_labels TEXT NOT NULL DEFAULT '[]';
