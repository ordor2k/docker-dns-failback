# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

# Install only what's needed
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY dns_failover_proxy.py healthcheck.py ./

# Drop privileges
RUN useradd -r -u 10001 dnspx
USER dnspx

# Default env (override in compose/env)
ENV LISTEN_ADDR=0.0.0.0 \
    LISTEN_PORT=5355 \
    PRIMARY_DNS=127.0.0.1:5335 \
    FALLBACK_DNS="1.1.1.1,8.8.8.8,9.9.9.9,1.0.0.1" \
    UDP_TIMEOUT=1.0 \
    TCP_TIMEOUT=2.0 \
    RETRIES_PER_UPSTREAM=1 \
    LOG_LEVEL=INFO

EXPOSE 5355/udp
EXPOSE 5355/tcp

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python /app/healthcheck.py || exit 1

CMD ["python", "/app/dns_failover_proxy.py"]
