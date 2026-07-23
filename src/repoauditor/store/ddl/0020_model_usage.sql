CREATE TABLE model_usage (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    pipeline_run_id    INTEGER REFERENCES pipeline_run(id) ON DELETE CASCADE,
    stage              TEXT NOT NULL,
    module             TEXT NOT NULL,
    prompt_version     TEXT NOT NULL,
    provider           TEXT NOT NULL,
    model              TEXT NOT NULL,
    usage_available    INTEGER NOT NULL CHECK (usage_available IN (0, 1)),
    input_tokens       INTEGER CHECK (input_tokens >= 0),
    output_tokens      INTEGER CHECK (output_tokens >= 0),
    cache_read_tokens  INTEGER CHECK (cache_read_tokens >= 0),
    cache_write_tokens INTEGER CHECK (cache_write_tokens >= 0),
    latency_ms         INTEGER NOT NULL CHECK (latency_ms >= 0),
    recorded_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_model_usage_pipeline ON model_usage (pipeline_run_id, id);
CREATE INDEX idx_model_usage_module ON model_usage (module, recorded_at);
