# Watchtower -- every workflow, one entry point.   `make help`
#
# dev (docker compose)  ->  ci (lint, schema, tests)  ->  staging (k8s)  ->  prod (k8s)
#
# Deployment is local: Kubernetes runs in Docker via k3d. `make promote` is
# the CD pipeline -- it deploys prod only if CI passes and staging's smoke
# test passes against the same images.

SHELL := /bin/bash
.DEFAULT_GOAL := help

PRODUCER_IMAGE := watchtower/producer:1.0
FLINK_IMAGE    := watchtower/flink:2.2.1
FLINK_TEST     := watchtower/flink:test
AIRFLOW_IMAGE  := watchtower/airflow:3.3.2
AIRFLOW_TEST   := watchtower/airflow:test
CLUSTER        := watchtower
ENV            ?= staging
NS             := watchtower-$(ENV)
BROKERS        ?= 3
RATE           ?= 1000
RENDER         := kubectl kustomize --load-restrictor LoadRestrictionsNone
ARCH           := $(shell docker version --format '{{.Server.Arch}}' 2>/dev/null)
NODE           := k3d-$(CLUSTER)-server-0

# Every image the cluster runs. All are loaded from the host, so nothing
# inside the cluster pulls from the internet.
CLUSTER_IMAGES := $(FLINK_IMAGE) $(PRODUCER_IMAGE) $(AIRFLOW_IMAGE) \
                  postgres:18.6-alpine \
                  ghcr.io/apache/flink-kubernetes-operator:1c895a3 \
                  ghcr.io/aiven-open/karapace:6.2.3 \
                  clickhouse/clickhouse-server:25.8.33 \
                  quay.io/strimzi/operator:1.2.0 \
                  quay.io/strimzi/kafka:1.2.0-kafka-4.3.1 \
                  prom/prometheus:v3.14.0 \
                  grafana/grafana:13.2.2

##@ Setup

.PHONY: help
help:  ## Show this help
	@awk 'BEGIN {FS = ":.*##"} /^##@/ {printf "\n\033[1m%s\033[0m\n", substr($$0, 5)} \
	  /^[a-zA-Z0-9_-]+:.*##/ {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: secrets
secrets:  ## Generate missing local secret files (never overwrites)
	@./deploy/k8s/scripts/secrets.sh

##@ Images

.PHONY: images
images: image-flink image-producer image-airflow  ## Build all runtime images

.PHONY: image-flink
image-flink:  ## Build the Flink streaming image (the live path)
	docker build --target runtime -t $(FLINK_IMAGE) -f docker/flink/Dockerfile .

.PHONY: image-flink-test
image-flink-test:  ## Build the Flink test image
	docker build --target test -t $(FLINK_TEST) -f docker/flink/Dockerfile .

.PHONY: image-airflow
image-airflow:  ## Build the Airflow image (orchestration: data quality, rollups, evaluation)
	docker build --target runtime -t $(AIRFLOW_IMAGE) -f docker/airflow/Dockerfile .

.PHONY: image-airflow-test
image-airflow-test:  ## Build the Airflow test image
	docker build --target test -t $(AIRFLOW_TEST) -f docker/airflow/Dockerfile .


.PHONY: image-producer
image-producer:  ## Build the producer image
	docker build -t $(PRODUCER_IMAGE) -f docker/producer/Dockerfile .

##@ Quality (CI runs exactly these)

.PHONY: lint
lint: image-flink-test  ## Ruff: pyflakes + syntax errors
	docker run --rm $(FLINK_TEST) python3 -m ruff check etl tools schemas tests producer orchestration monitor

.PHONY: test-unit
test-unit: image-flink-test  ## Engine-free unit tests (etl/core, config, registry): seconds
	docker run --rm $(FLINK_TEST) python3 -m pytest -q -p no:cacheprovider tests/unit

.PHONY: test
test: test-flink test-airflow  ## Every suite: unit, the Flink job, the DAGs

.PHONY: test-flink
test-flink: image-flink-test  ## Unit tests + the Flink job end to end on a local mini-cluster
	docker run --rm $(FLINK_TEST) python3 -m pytest -q -p no:cacheprovider tests/unit tests/flink

.PHONY: test-airflow
test-airflow: image-airflow-test  ## The DAGs parse and are wired as documented; their ops and the evaluator
	docker run --rm $(AIRFLOW_TEST)

.PHONY: render
render:  ## Render both overlays -- catches broken manifests without a cluster
	@for env in staging prod; do \
	  $(RENDER) deploy/k8s/overlays/$$env > /dev/null && echo "render $$env: OK" || exit 1; \
	done

.PHONY: schema-check
schema-check:  ## Is schemas/build_event.avsc compatible with the registry? (dev registry)
	python3 tools/schema_registry.py check --url http://localhost:8081

.PHONY: ci
ci: lint test render  ## Everything CI runs

##@ Dev (docker compose)

.PHONY: dev-up
dev-up: secrets image-flink image-producer  ## Start the dev stack (Flink live path)
	docker compose up -d
	@echo "flink ui: http://localhost:8082   job metrics: http://localhost:9250/metrics"

# One command from a clean checkout to live results. 10 events/s by default:
# the 1,000/s stack alone fills a ~4 GB Docker VM (see airflow-up), and 10/s
# is plenty to see every part work. QS_RATE=100 make quickstart for more.
QS_RATE ?= 10

.PHONY: quickstart
quickstart: dev-up  ## One command: secrets, images, the stack, a producer (QS_RATE=10 events/s) and a live check
	LOGS_PER_SECOND=$(QS_RATE) docker compose --profile sim up -d --force-recreate --no-deps producer
	@echo "waiting for the first stored events (up to 3 min)..."
	@for i in $$(seq 1 36); do \
	  n=$$(docker exec watchtower-clickhouse sh -c 'clickhouse-client --user watchtower --password "$$(cat /run/secrets/clickhouse_password)" -q "SELECT count() FROM watchtower.security_events"' 2>/dev/null); \
	  [ "$${n:-0}" -gt 0 ] 2>/dev/null && break; sleep 5; done
	@docker exec watchtower-clickhouse sh -c 'clickhouse-client --user watchtower --password "$$(cat /run/secrets/clickhouse_password)" --format PrettyCompact -q "SELECT recommended_action AS action, count() AS events, countIf(notEmpty(rule_hits)) AS with_rule_hits FROM watchtower.security_events GROUP BY action ORDER BY action"'
	@echo ""
	@echo "running at $(QS_RATE) events/s. Next:"
	@echo "  make latency     end-to-end latency, last minute"
	@echo "  make evaluate    detection vs the simulator's ground truth (give it a few minutes of traffic first)"
	@echo "  make airflow-up  add Airflow (lowers the producer to 100/s)"
	@echo "  make dev-down    stop everything (keeps the data)"

.PHONY: dev-down
dev-down:  ## Stop the dev stack (keeps volumes)
	docker compose --profile sim --profile airflow --profile monitoring down

# Needs no build: Prometheus and Grafana are stock images, the monitor runs
# the mounted monitor/ on the producer image. ClickHouse is restarted only
# when it has not opened its Prometheus port yet (9363, 2493 in /proc/net/tcp):
# config.d is read at start.
.PHONY: monitor-up
monitor-up: secrets  ## Prometheus + Grafana + the live-audit exporter; Grafana on :3000
	@docker exec watchtower-clickhouse grep -qi ':2493 ' /proc/net/tcp /proc/net/tcp6 \
	  || docker compose up -d --force-recreate --no-deps clickhouse
	docker compose --profile monitoring up -d --no-deps monitor prometheus grafana
	@echo "grafana: http://localhost:3000 (live audit; admin / secrets/grafana_admin_password to edit)"
	@echo "prometheus: http://localhost:9090   exporter: http://localhost:9400/metrics"

.PHONY: monitor-down
monitor-down:  ## Stop the monitoring stack (keeps its data)
	docker compose --profile monitoring stop monitor prometheus grafana

# The producer runs at 100/s here, not 1,000: the 1,000/s stack alone fills
# a ~4 GB Docker VM's swap, and Airflow needs ~0.5 GB while a task runs.
.PHONY: airflow-up
airflow-up: secrets image-flink image-airflow  ## Dev stack + Airflow (producer at 100/s); UI on :8080
	LOGS_PER_SECOND=$${LOGS_PER_SECOND:-100} docker compose --profile sim --profile airflow up -d
	@docker exec -i watchtower-clickhouse sh -c \
	  'clickhouse-client --user watchtower --password "$$(cat /run/secrets/clickhouse_password)" --multiquery' \
	  < clickhouse/init/04_orchestration.sql
	@echo "airflow ui: http://localhost:8080   (admin / secrets/airflow_admin_password)"

.PHONY: dev-logs
dev-logs:  ## Follow the streaming job's logs
	docker compose logs -f flink-jobmanager flink-taskmanager

.PHONY: latency
latency:  ## End-to-end latency, from ClickHouse: event created -> row stored (dev)
	@docker exec watchtower-clickhouse sh -c 'clickhouse-client --user watchtower --password "$$(cat /run/secrets/clickhouse_password)" -q "\
	  SELECT count() AS events, round(count()/60) AS per_sec, \
	    quantile(0.5)(l) AS p50_ms, quantile(0.95)(l) AS p95_ms, quantile(0.99)(l) AS p99_ms, max(l) AS max_ms \
	  FROM (SELECT toUnixTimestamp64Milli(ingested_at) - toUnixTimestamp64Milli(timestamp) AS l FROM watchtower.security_events \
	        WHERE ingested_at > now64(3) - INTERVAL 60 SECOND) FORMAT PrettyCompactMonoBlock"'

.PHONY: ch-migrate
ch-migrate:  ## Apply clickhouse/init/*.sql to the running dev ClickHouse (idempotent)
	@for f in clickhouse/init/*.sql; do \
	  echo "applying $$f"; \
	  docker exec -i watchtower-clickhouse sh -c \
	    'clickhouse-client --user watchtower --password "$$(cat /run/secrets/clickhouse_password)" --multiquery' < $$f || exit 1; \
	done

.PHONY: ch-recreate-ingest
ch-recreate-ingest:  ## Apply changed Kafka-engine settings (03_streaming_ingest.sql) to the dev ClickHouse
	@for f in clickhouse/maintenance_drop_streaming_ingest.sql clickhouse/init/03_streaming_ingest.sql; do \
	  echo "applying $$f"; \
	  docker exec -i watchtower-clickhouse sh -c \
	    'clickhouse-client --user watchtower --password "$$(cat /run/secrets/clickhouse_password)" --multiquery' < $$f || exit 1; \
	done

.PHONY: ch-relayout
ch-relayout:  ## Move an existing security_events onto the 01_schema.sql layout (stop writers first)
	python3 tools/relayout_security_events.py

.PHONY: ch-bench
ch-bench:  ## Benchmark the engineer/evaluator/latency queries: make ch-bench TABLES="security_events"
	python3 tools/bench_queries.py $${TABLES:-security_events}

.PHONY: ch-migrate-k8s
ch-migrate-k8s:  ## Apply clickhouse/init/*.sql to ENV's ClickHouse (idempotent)
	@for f in clickhouse/init/*.sql; do \
	  echo "applying $$f to $(NS)"; \
	  kubectl -n $(NS) exec -i clickhouse-0 -- sh -c \
	    'clickhouse-client --user watchtower --password "$$CLICKHOUSE_PASSWORD" --multiquery' < $$f || exit 1; \
	done

.PHONY: pipeline-health
pipeline-health:  ## The latest end-to-end verdict from Airflow, stage by stage (dev)
	@docker exec watchtower-clickhouse sh -c 'clickhouse-client --user watchtower --password "$$(cat /run/secrets/clickhouse_password)" -q "\
	  SELECT stage, check_name, if(passed, '\''ok'\'', upper(severity)) AS result, detail FROM watchtower.pipeline_health \
	  WHERE run_id = (SELECT argMax(run_id, checked_at) FROM watchtower.pipeline_health) \
	  ORDER BY stage, check_name FORMAT PrettyCompactMonoBlock"'

.PHONY: evaluate
evaluate:  ## Detection vs ground truth: ok/alert/quarantine per scenario (dev)
	python3 tools/evaluate_detection.py --minutes $${MINUTES:-15}

.PHONY: produce
produce:  ## Synthetic traffic from the host (Ctrl-C to stop)
	KAFKA_BROKER=localhost:9092 SCHEMA_REGISTRY_URL=http://localhost:8081 \
	  python3 producer/build_log_producer.py

##@ Kubernetes (k3d)

# Images are loaded BEFORE Strimzi is installed. The other way round, the
# operator pod pulls its image from quay.io inside the node -- slow enough
# on a poor link to blow the rollout timeout, and it breaks the rule that
# nothing inside the cluster downloads from the internet.
.PHONY: cluster-up
cluster-up:  ## Create the k3d cluster, load all images, install Strimzi + Flink operator
	@k3d cluster list $(CLUSTER) >/dev/null 2>&1 || k3d cluster create --config deploy/k3d/cluster.yaml
	$(MAKE) images-import
	./deploy/k8s/scripts/install-strimzi.sh
	./deploy/k8s/scripts/install-flink-operator.sh

.PHONY: cluster-down
cluster-down:  ## Delete the k3d cluster and everything in it
	k3d cluster delete $(CLUSTER)

# Not `k3d image import`: with Docker Desktop's containerd image store it
# saves multi-arch index tarballs referencing platforms never pulled, the
# import fails part-way -- and k3d still reports "Successfully imported".
# Saving a single platform works; every image is then verified present.
.PHONY: images-import
images-import: images  ## Load every image into the cluster, then verify
	@for img in $(CLUSTER_IMAGES); do \
	  docker image inspect $$img >/dev/null 2>&1 || docker pull -q $$img >/dev/null; \
	  echo "importing $$img"; \
	  docker save --platform linux/$(ARCH) $$img \
	    | docker exec -i $(NODE) ctr -n k8s.io images import --platform linux/$(ARCH) - >/dev/null; \
	done
	@missing=0; for img in $(CLUSTER_IMAGES); do \
	  name=$${img%:*}; tag=$${img##*:}; \
	  docker exec $(NODE) crictl images | awk '{print $$1":"$$2}' | grep -qE "(^|/)$${name}:$${tag}$$" \
	    || { echo "MISSING in cluster: $$img"; missing=1; }; \
	done; [ $$missing = 0 ] && echo "all $(words $(CLUSTER_IMAGES)) images present in $(NODE)"

.PHONY: deploy
deploy:  ## Deploy ENV (staging|prod)
	./deploy/k8s/scripts/secrets.sh $(NS)
	kubectl -n $(NS) delete job schema-init --ignore-not-found >/dev/null
	$(RENDER) deploy/k8s/overlays/$(ENV) | ./deploy/k8s/scripts/keep-scaled-replicas.py $(NS) \
	  | kubectl apply --server-side --force-conflicts -f -
	kubectl -n $(NS) wait kafka/watchtower --for=condition=Ready --timeout=600s
	kubectl -n $(NS) wait job/schema-init --for=condition=Complete --timeout=300s
	kubectl -n $(NS) wait flinkdeployment/stream --for=jsonpath='{.status.jobStatus.state}'=RUNNING --timeout=600s
	kubectl -n $(NS) rollout status deploy/producer --timeout=300s

.PHONY: smoke
smoke:  ## End-to-end smoke test of ENV
	./deploy/k8s/scripts/smoke-test.sh $(NS)

.PHONY: promote
promote: ci images-import  ## CD: ci -> staging -> smoke -> prod -> smoke
	$(MAKE) deploy ENV=staging
	$(MAKE) smoke ENV=staging
	$(MAKE) deploy ENV=prod
	$(MAKE) smoke ENV=prod

# Brokers normally follow the HPA (kafka-brokers). Pinning sets its min and
# max to BROKERS; Strimzi then scales the pool and Cruise Control moves the
# partitions -- onto new brokers after they join, off old ones BEFORE they
# are removed. `make unpin-kafka` hands the count back to the autoscaler.
.PHONY: scale-kafka
scale-kafka:  ## Pin ENV's brokers to BROKERS (up or down); partitions follow
	kubectl -n $(NS) patch hpa kafka-brokers --type merge \
	  -p '{"spec":{"minReplicas":$(BROKERS),"maxReplicas":$(BROKERS)}}'
	@echo "waiting for $(BROKERS) broker(s) and the rebalance..."
	@for i in $$(seq 1 120); do \
	  n=$$(kubectl -n $(NS) get kafkanodepool brokers -o jsonpath='{.status.replicas}'); \
	  [ "$$n" = "$(BROKERS)" ] && break; sleep 10; \
	done
	kubectl -n $(NS) wait kafka/watchtower --for=condition=Ready --timeout=600s
	@kubectl -n $(NS) get kafka watchtower -o jsonpath='{range .status.autoRebalance}{.state}{"  "}{.lastTransitionTime}{"\n"}{end}'

.PHONY: unpin-kafka
unpin-kafka:  ## Give ENV's broker count back to the autoscaler
	@min=$$(kubectl kustomize --load-restrictor LoadRestrictionsNone deploy/k8s/overlays/$(ENV) \
	  | python3 -c 'import sys,yaml;h=[d for d in yaml.safe_load_all(sys.stdin) if d and d["kind"]=="HorizontalPodAutoscaler"][0]["spec"];print(h["minReplicas"],h["maxReplicas"])'); \
	set -- $$min; kubectl -n $(NS) patch hpa kafka-brokers --type merge \
	  -p "{\"spec\":{\"minReplicas\":$$1,\"maxReplicas\":$$2}}"

# Change the synthetic load without a redeploy -- to watch the pipeline
# scale out under a surge and back in after it.
.PHONY: load
load:  ## Set ENV's total producer rate, split across replicas: make load RATE=10000
	@replicas=$$(( ($(RATE) + 1999) / 2000 )); \
	echo "$(RATE) events/s = $$replicas producer(s) x $$(( $(RATE) / replicas ))/s"; \
	kubectl -n $(NS) set env deploy/producer LOGS_PER_SECOND=$$(( $(RATE) / replicas )) && \
	kubectl -n $(NS) scale deploy/producer --replicas=$$replicas
	kubectl -n $(NS) rollout status deploy/producer --timeout=180s

.PHONY: watch-scaling
watch-scaling:  ## TaskManagers, parallelism, brokers, lag and latency, every 15 s
	@./deploy/k8s/scripts/watch-scaling.sh $(NS)

.PHONY: status
status:  ## Pods, brokers and memory for ENV
	@kubectl -n $(NS) get kafka,kafkanodepool,kafkatopic 2>/dev/null
	@echo; kubectl -n $(NS) get pods -o wide
	@echo; kubectl top pods -n $(NS) 2>/dev/null || true

.PHONY: grafana
grafana:  ## Grafana on http://localhost:3000 (admin / secrets/grafana_admin_password)
	kubectl -n $(NS) port-forward svc/grafana 3000:3000

.PHONY: airflow-ui
airflow-ui:  ## Airflow on http://localhost:8080 (admin / secrets/airflow_admin_password)
	kubectl -n $(NS) port-forward svc/airflow-api-server 8080:8080

.PHONY: prometheus
prometheus:  ## Prometheus on http://localhost:9090
	kubectl -n $(NS) port-forward svc/prometheus 9090:9090
