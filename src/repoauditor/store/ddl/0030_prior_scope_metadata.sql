-- Scope metadata describes applicability and uncertainty; it does not change distributions.
-- Dates/vintages remain NULL when the configured citation does not establish them.
ALTER TABLE prior_source ADD COLUMN target_population TEXT;
ALTER TABLE prior_source ADD COLUMN effective_date TEXT;
ALTER TABLE prior_source ADD COLUMN data_vintage TEXT;
ALTER TABLE prior_source ADD COLUMN aleatory_representation TEXT;
ALTER TABLE prior_source ADD COLUMN epistemic_status TEXT;
