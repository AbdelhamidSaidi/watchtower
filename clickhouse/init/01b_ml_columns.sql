-- The detector's model columns were llm_* while a Groq LLM judged the
-- grey zone; a LightGBM model scored in the stream replaces it
-- (etl/core/ml.py). Fresh installs get ml_* from 01_schema.sql; this renames
-- them on an existing install. It must run BEFORE 02_*.sql, which recreates
-- the suspicious-events view over these columns -- hence the name.
--
-- The Kafka intake (03_streaming_ingest.sql) cannot be altered, only
-- recreated: after this, run `make ch-recreate-ingest`.

ALTER TABLE watchtower.security_events RENAME COLUMN IF EXISTS llm_score TO ml_score;
ALTER TABLE watchtower.security_events RENAME COLUMN IF EXISTS llm_reason TO ml_reason;
ALTER TABLE watchtower.security_events RENAME COLUMN IF EXISTS llm_model TO ml_model;

ALTER TABLE watchtower.suspicious_events RENAME COLUMN IF EXISTS llm_score TO ml_score;
ALTER TABLE watchtower.suspicious_events RENAME COLUMN IF EXISTS llm_reason TO ml_reason;
