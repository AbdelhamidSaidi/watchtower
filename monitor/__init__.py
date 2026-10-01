"""The live system's auditor: one exporter, Prometheus text on :9400/metrics.

Flink and ClickHouse already export their own metrics. This package adds
what only Watchtower can say about itself -- measured from outside the
pipeline, from what it stored, what it decided, and what it should have
decided:

  stored    end-to-end latency (a histogram and exact percentiles), decisions
            per action, which model version scored, the score distribution
  accuracy  rules, model and final decision against the simulator's ground
            truth, on a hashed sample of every event (synthetic traffic only)
  model     the active model, its holdout metrics, its promotions
  learning  the AI reviewer's verdicts, training labels
  ops       Airflow's verdict tables: pipeline checks, data quality, the
            6-hourly detection evaluation, refused messages
  kafka     end offsets and consumer-group lag
  services  probes: registry, ClickHouse, Flink's REST API, Airflow
  vm        the Docker VM's memory, swap, pressure and OOM kills

Every collector runs on its own thread and interval; a scrape only renders
what they last published, so its cost never depends on ClickHouse or Kafka.
A collector that fails is withdrawn from the output (never shown stale) and
says so in watchtower_monitor_collector_up.

The exporter only reads: ClickHouse queries run readonly with a memory cap,
and Kafka is read without a consumer group.
"""
