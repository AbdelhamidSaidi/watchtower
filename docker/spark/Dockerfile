# Watchtower Spark image.
#
# Stages:
#   base     everything the pipeline needs at runtime
#   test     base + pytest/ruff + the test suite   (docker build --target test)
#   runtime  the default target; identical to base
#
# The stock apache/spark image is missing several things this pipeline
# needs. Each was first hit as a runtime failure; they belong here:
#
#   1. pandas / pyarrow -- applyInPandasWithState cannot import without them.
#   2. the Kafka and Avro jars -- otherwise every submit needs --packages.
#   3. a spark-owned .ivy2 -- a named volume mounted on a path absent from
#      the image is created root-owned, and the image runs as uid 185.
#   4. executor PYTHONPATH -- cloudpickle serialises the stateful function in
#      features.py BY REFERENCE, so executors import it themselves.
#   5. the code itself -- Kubernetes runs an immutable image, it cannot rely
#      on a bind mount. Compose still mounts the source over it for dev.

FROM apache/spark:3.5.9-scala2.12-java17-python3-r-ubuntu AS base

USER root

# Versions are pinned to what Spark 3.5.9 / Scala 2.12 actually resolves --
# taken from the ivy cache after a real --packages run, not guessed.
ARG SPARK_VERSION=3.5.9
ARG SCALA_BINARY=2.12
ARG KAFKA_CLIENTS_VERSION=3.4.1
ARG COMMONS_POOL2_VERSION=2.11.1

# Installed from the same file a local environment uses, so the two cannot
# drift. --timeout/--retries: pip's default 15s read timeout fails the whole
# build on a slow link (it did, on PyPI). Copied on its own: this layer only rebuilds when deps change, not
# on every edit to the ETL source.
COPY etl/requirements.txt /tmp/requirements.txt
RUN python3 -m pip install --no-cache-dir --timeout 120 --retries 10 -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

# Only the jars the image does not already ship. snappy-java and lz4-java are
# already in /opt/spark/jars; adding them again risks a classpath conflict.
#
# urllib rather than curl: the base image has Python but not necessarily
# curl, and this avoids an apt-get layer.
RUN SPARK_VERSION="${SPARK_VERSION}" \
    SCALA_BINARY="${SCALA_BINARY}" \
    KAFKA_CLIENTS_VERSION="${KAFKA_CLIENTS_VERSION}" \
    COMMONS_POOL2_VERSION="${COMMONS_POOL2_VERSION}" \
    python3 - <<'PY'
import os
import socket
import urllib.request

# urlretrieve has NO default timeout: a stalled connection to Maven hangs
# the build forever with no output. This caps it.
socket.setdefaulttimeout(60)

M = "https://repo1.maven.org/maven2"
SPARK = os.environ["SPARK_VERSION"]
SCALA = os.environ["SCALA_BINARY"]
KAFKA = os.environ["KAFKA_CLIENTS_VERSION"]
POOL = os.environ["COMMONS_POOL2_VERSION"]

jars = [
    f"{M}/org/apache/spark/spark-sql-kafka-0-10_{SCALA}/{SPARK}/spark-sql-kafka-0-10_{SCALA}-{SPARK}.jar",
    f"{M}/org/apache/spark/spark-token-provider-kafka-0-10_{SCALA}/{SPARK}/spark-token-provider-kafka-0-10_{SCALA}-{SPARK}.jar",
    f"{M}/org/apache/kafka/kafka-clients/{KAFKA}/kafka-clients-{KAFKA}.jar",
    f"{M}/org/apache/commons/commons-pool2/{POOL}/commons-pool2-{POOL}.jar",
    # from_avro -- decoding Confluent-framed messages in transform/parse.py
    f"{M}/org/apache/spark/spark-avro_{SCALA}/{SPARK}/spark-avro_{SCALA}-{SPARK}.jar",
]

for url in jars:
    name = url.rsplit("/", 1)[-1]
    print("fetching", name, flush=True)
    for attempt in (1, 2, 3):
        try:
            urllib.request.urlretrieve(url, f"/opt/spark/jars/{name}")
            break
        except Exception as exc:
            print(f"  attempt {attempt} failed: {exc}", flush=True)
            if attempt == 3:
                raise
PY

# /opt/spark/conf does not exist in the base image and SPARK_CONF_DIR is
# unset, so Spark falls back to $SPARK_HOME/conf -- which has to be created.
RUN mkdir -p /opt/spark/conf \
    && printf 'spark.executorEnv.PYTHONPATH /opt/watchtower/etl:/opt/watchtower\n' \
        > /opt/spark/conf/spark-defaults.conf \
    && chown -R 185:185 /opt/spark/conf

# Pre-created with the right owner so fresh named volumes and PVCs mounted
# here inherit it.
RUN mkdir -p /opt/spark/work-dir/.ivy2 /var/lib/watchtower/checkpoints \
    && chown -R 185:185 /opt/spark/work-dir/.ivy2 /var/lib/watchtower

COPY --chown=185:185 schemas /opt/watchtower/schemas
COPY --chown=185:185 tools /opt/watchtower/tools
COPY --chown=185:185 etl /opt/watchtower/etl

# Driver side of the same import problem.
ENV PYTHONPATH=/opt/watchtower/etl:/opt/watchtower

# /metrics, served by the Spark driver (etl/observability/metrics.py)
EXPOSE 9108

USER 185


FROM base AS test

USER root
COPY etl/requirements-dev.txt /tmp/requirements-dev.txt
COPY etl/requirements.txt /tmp/requirements.txt
RUN python3 -m pip install --no-cache-dir --timeout 120 --retries 10 -r /tmp/requirements-dev.txt \
    && rm /tmp/requirements*.txt

COPY --chown=185:185 tests /opt/watchtower/tests
# Linted with everything else; the producer's deps are not needed to lint it.
COPY --chown=185:185 producer /opt/watchtower/producer
# The DAGs' ops are plain Python and tested here too; the DAG files
# themselves need Airflow, so tests/orchestration/test_dags.py skips here
# and runs in the Airflow image (`make test-airflow`).
COPY --chown=185:185 orchestration /opt/watchtower/orchestration
COPY --chown=185:185 pyproject.toml /opt/watchtower/pyproject.toml

# pyspark lives under /opt/spark/python, not site-packages.
ENV PYTHONPATH=/opt/watchtower/etl:/opt/watchtower:/opt/spark/python:/opt/spark/python/lib/py4j-0.10.9.7-src.zip

USER 185
WORKDIR /opt/watchtower
CMD ["python3", "-m", "pytest", "-q", "tests"]


FROM base AS runtime
