-- Used by `make ch-recreate-ingest` before re-running 03_streaming_ingest.sql:
-- Kafka-engine settings cannot be ALTERed, only recreated. The consumer
-- groups keep their offsets in Kafka, so the recreated queues resume where
-- these stop.
DROP VIEW IF EXISTS watchtower.security_events_from_queue;
DROP VIEW IF EXISTS watchtower.sink_errors_from_events_queue;
DROP VIEW IF EXISTS watchtower.rejected_events_from_queue;
DROP VIEW IF EXISTS watchtower.sink_errors_from_rejected_queue;
DROP TABLE IF EXISTS watchtower.security_events_queue;
DROP TABLE IF EXISTS watchtower.rejected_events_queue;
