# Watchtower synthetic traffic producer.
#
# Small on purpose: plain Python, two dependencies. It shares the wire
# contract (schemas/) with the pipeline so both sides agree on the format.

FROM python:3.12-slim

RUN useradd --uid 10001 --create-home producer

COPY producer/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --timeout 120 --retries 10 -r /tmp/requirements.txt && rm /tmp/requirements.txt

COPY --chown=10001:10001 schemas /app/schemas
COPY --chown=10001:10001 producer /app/producer

USER 10001
WORKDIR /app
ENV PYTHONUNBUFFERED=1

CMD ["python", "producer/security_log_producer.py"]
