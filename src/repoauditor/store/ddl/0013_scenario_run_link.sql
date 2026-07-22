-- Version each persisted scenario snapshot by the Monte Carlo audit run that produced it.
-- Nullable preserves legacy and standalone build_scenarios records.
ALTER TABLE risk_scenario
    ADD COLUMN simulation_run_id INTEGER REFERENCES simulation_run(id) ON DELETE CASCADE;

CREATE INDEX idx_risk_scenario_simulation_run
    ON risk_scenario (simulation_run_id, id);
