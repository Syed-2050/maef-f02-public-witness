FROM python:3.13-alpine
RUN addgroup -g 65532 -S maefworker && adduser -S -D -H -u 65532 -G maefworker maefworker
COPY --chown=65532:65532 worker_probe.py /opt/witness/worker_probe.py
RUN chmod 0555 /opt/witness/worker_probe.py
