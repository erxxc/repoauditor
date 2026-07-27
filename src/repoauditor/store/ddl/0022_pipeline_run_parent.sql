-- Link separately budgeted continuation batches into one logical scan chain.
ALTER TABLE pipeline_run
    ADD COLUMN parent_run_id INTEGER REFERENCES pipeline_run(id);

CREATE INDEX idx_pipeline_run_parent ON pipeline_run (parent_run_id);
