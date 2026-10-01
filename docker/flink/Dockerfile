# The streaming job: Flink 2.2 + PyFlink, running the etl/core logic. The
# `test` stage also runs the engine-free tests and ruff (make test, make lint).
#
# One image for every Flink role (jobmanager, taskmanager) in compose and
# in Kubernetes.
ARG FLINK_VERSION=2.2.1
# Java 11, not 17: PyFlink's THREAD mode (Python embedded in the JVM, see
# config.PYTHON_EXECUTION_MODE) goes through PEMJA, whose Java side reads a
# JDK field removed after Java 11 -- on 17 the job fails at startup with
# NoSuchFieldException: loadedLibraryNames. Flink 2.2 supports 11, 17, 21.
FROM flink:${FLINK_VERSION}-scala_2.12-java11 AS runtime

ARG FLINK_VERSION
ARG KAFKA_CONNECTOR=5.0.0-2.2

USER root

# PyFlink ships x86_64 wheels only; on arm64 its Cython extensions build
# from source, hence the compiler. Everything it depends on has wheels.
# libpython3.12t64: the SHARED libpython. Ubuntu's python3 binary is
# statically linked, and thread mode embeds Python in the JVM through this
# library -- without it: UnsatisfiedLinkError "absolute path ... None".
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-pip libpython3.12t64 python3-dev build-essential \
    && ln -sf /usr/bin/python3 /usr/bin/python \
    && rm -rf /var/lib/apt/lists/*

# PyFlink WITHOUT apache-flink-libraries: that package is a 298 MB copy of
# the Flink jars this image already has in /opt/flink (FLINK_HOME).
# --break-system-packages: the base is Ubuntu 24.04 (PEP 668), and this
# single-purpose image's system Python exists only to run the job.
COPY docker/flink/requirements.txt /tmp/requirements.txt
RUN PIP="pip3 install --no-cache-dir --timeout 120 --retries 10 --break-system-packages" \
    && $PIP -r /tmp/requirements.txt \
    && $PIP --no-deps "apache-flink==${FLINK_VERSION}" \
    && python3 -c "import pyflink.datastream, fastavro, pemja; print('pyflink ok')" \
    && apt-get purge -y build-essential python3-dev && apt-get autoremove -y

# Python support and the Kafka connector on the classpath of every role.
# (Prometheus metrics need nothing: plugins/metrics-prometheus ships in the image.)
RUN cp /opt/flink/opt/flink-python-${FLINK_VERSION}.jar /opt/flink/lib/ \
    && wget -q -O /opt/flink/lib/flink-sql-connector-kafka-${KAFKA_CONNECTOR}.jar \
       https://repo1.maven.org/maven2/org/apache/flink/flink-sql-connector-kafka/${KAFKA_CONNECTOR}/flink-sql-connector-kafka-${KAFKA_CONNECTOR}.jar \
    && mkdir -p /var/lib/watchtower/flink-checkpoints && chown -R flink:flink /var/lib/watchtower /opt/flink/lib

COPY --chown=flink:flink docker/flink/run-job.sh /opt/watchtower/run-job.sh
COPY --chown=flink:flink schemas /opt/watchtower/schemas
COPY --chown=flink:flink etl /opt/watchtower/etl
ENV PYTHONPATH=/opt/watchtower/etl:/opt/watchtower

USER flink

# --- test: the unit tests, the job on a local Flink mini-cluster, lint ----
FROM runtime AS test
USER root
# LightGBM (to prove the compiled scorer equals it) needs the OpenMP runtime.
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 && rm -rf /var/lib/apt/lists/*
RUN pip3 install --no-cache-dir --timeout 120 --retries 10 --break-system-packages \
      pytest==9.1.1 ruff==0.16.8 lightgbm==4.7.0
COPY --chown=flink:flink pyproject.toml /opt/watchtower/pyproject.toml
COPY --chown=flink:flink tests /opt/watchtower/tests
# Linted with everything else (make lint); their own tests run in the
# Airflow image.
COPY --chown=flink:flink tools /opt/watchtower/tools
COPY --chown=flink:flink producer /opt/watchtower/producer
COPY --chown=flink:flink orchestration /opt/watchtower/orchestration
COPY --chown=flink:flink monitor /opt/watchtower/monitor
WORKDIR /opt/watchtower
USER flink
