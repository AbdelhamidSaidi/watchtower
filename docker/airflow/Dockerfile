# Watchtower orchestration: Airflow 3 running the DAGs in orchestration/dags.
#
# The DAGs' work (orchestration/ops, tools/evaluate_detection.py) talks to
# ClickHouse over HTTP and to Kafka directly, so no Airflow provider is
# needed for either; the postgres provider is for Airflow's own metadata
# database. The slim base carries Airflow and nothing else -- ~1.1 GB
# against ~2 GB for the full image with every provider.
#
#   runtime  what compose and Kubernetes run
#   test     runtime + pytest + tests/, for `make test-airflow`

ARG AIRFLOW_VERSION=3.3.2
ARG PYTHON_VERSION=3.12

FROM apache/airflow:slim-${AIRFLOW_VERSION}-python${PYTHON_VERSION} AS runtime
ARG AIRFLOW_VERSION
ARG PYTHON_VERSION

# Against Airflow's constraints for this exact version: the set its
# release was tested with, so a provider cannot drag a core dependency
# somewhere Airflow was never run.
COPY docker/airflow/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --timeout 120 --retries 10 \
      "apache-airflow==${AIRFLOW_VERSION}" -r /tmp/requirements.txt \
      --constraint "https://raw.githubusercontent.com/apache/airflow/constraints-${AIRFLOW_VERSION}/constraints-${PYTHON_VERSION}.txt"

# Only what the DAGs import: settings (etl/config.py), the wire contract,
# the evaluator, and the DAGs with their ops.
COPY --chown=airflow:root etl/config.py /opt/watchtower/etl/config.py
COPY --chown=airflow:root schemas /opt/watchtower/schemas
COPY --chown=airflow:root tools/evaluate_detection.py /opt/watchtower/tools/evaluate_detection.py
COPY --chown=airflow:root orchestration /opt/watchtower/orchestration
COPY --chown=airflow:root --chmod=755 docker/airflow/start.sh /opt/watchtower/start.sh

ENV PYTHONPATH=/opt/watchtower \
    AIRFLOW__CORE__DAGS_FOLDER=/opt/watchtower/orchestration/dags \
    AIRFLOW__CORE__LOAD_EXAMPLES=False \
    AIRFLOW__CORE__EXECUTOR=LocalExecutor \
    AIRFLOW__CORE__PARALLELISM=4 \
    AIRFLOW__CORE__SIMPLE_AUTH_MANAGER_PASSWORDS_FILE=/opt/airflow/passwords.json \
    AIRFLOW__API__WORKERS=1 \
    AIRFLOW__API__EXPOSE_CONFIG=False \
    AIRFLOW__DAG_PROCESSOR__REFRESH_INTERVAL=60 \
    AIRFLOW__SCHEDULER__ENABLE_HEALTH_CHECK=True \
    PYTHONUNBUFFERED=1

ENTRYPOINT ["/usr/bin/dumb-init", "--", "/opt/watchtower/start.sh"]
CMD []

FROM runtime AS test
ARG AIRFLOW_VERSION
ARG PYTHON_VERSION
# pytest itself is not in the constraints; its dependencies are, so they
# stay at the versions Airflow runs with.
RUN pip install --no-cache-dir "pytest==9.1.1" \
      --constraint "https://raw.githubusercontent.com/apache/airflow/constraints-${AIRFLOW_VERSION}/constraints-${PYTHON_VERSION}.txt"
COPY --chown=airflow:root tests /opt/watchtower/tests
COPY --chown=airflow:root pyproject.toml /opt/watchtower/pyproject.toml
WORKDIR /opt/watchtower
ENTRYPOINT []
CMD ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/orchestration"]
