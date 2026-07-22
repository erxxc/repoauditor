ALTER TABLE risk_scenario ADD COLUMN exposure_factors TEXT NOT NULL DEFAULT '[]';
ALTER TABLE risk_scenario ADD COLUMN control_strengths TEXT NOT NULL DEFAULT '[]';
ALTER TABLE risk_scenario ADD COLUMN loss_scale REAL NOT NULL DEFAULT 1.0;

CREATE TABLE scenario_input (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    risk_scenario_id INTEGER NOT NULL REFERENCES risk_scenario(id) ON DELETE CASCADE,
    repo_id          TEXT NOT NULL,
    scenario_name    TEXT NOT NULL,
    input_name       TEXT NOT NULL CHECK (input_name IN ('exposure', 'control_strength', 'loss_scale')),
    value            REAL NOT NULL,
    origin           TEXT NOT NULL CHECK (origin IN ('derived', 'analyst_override', 'conservative_default')),
    source           TEXT NOT NULL,
    detail           TEXT,
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (risk_scenario_id, input_name)
);

CREATE INDEX idx_scenario_input_repo ON scenario_input (repo_id, risk_scenario_id);
