# syntax=docker/dockerfile:1
# Official python manifest digest resolved from registry-1.docker.io.
ARG BASE_IMAGE=python:3.12-slim-trixie@sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d
FROM ${BASE_IMAGE} AS builder
ARG THREEPROXY_VERSION=0.9.6
ARG THREEPROXY_SHA256=5645111fb146faaaf260c27f0e07e510e8530a7e8a18369474cc8abbedbc9c9a
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends build-essential curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
RUN curl --fail --location --proto '=https' --tlsv1.2 \
      "https://codeload.github.com/3proxy/3proxy/tar.gz/refs/tags/${THREEPROXY_VERSION}" -o /tmp/3proxy.tar.gz \
    && echo "${THREEPROXY_SHA256}  /tmp/3proxy.tar.gz" | sha256sum --check --strict \
    && tar xzf /tmp/3proxy.tar.gz --strip-components=1 \
    && make -f Makefile.Linux && strip bin/3proxy

# Compile Python source distributions in a disposable, target-platform stage.
# Runtime dependency versions and accepted wheel/sdist SHA256 values remain locked.
FROM ${BASE_IMAGE} AS python-builder
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends build-essential pkg-config libffi-dev \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /build/requirements.txt
RUN pip install --no-cache-dir --require-hashes --prefix=/install -r /build/requirements.txt

FROM ${BASE_IMAGE} AS runtime
ARG VCS_REF=unknown
LABEL org.opencontainers.image.source="https://github.com/bscongluanbui/clbip" \
      org.opencontainers.image.title="CLB IPv6 Proxy Manager" \
      org.opencontainers.image.description="Linux IPv6 proxy manager with isolated worker and dashboard roles" \
      org.opencontainers.image.revision="${VCS_REF}"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    DATA_DIR=/app/data GUI_PORT=7070 GUI_BIND=127.0.0.1 \
    WORKER_SOCKET=/run/ipv6-manager/worker.sock APP_ROLE=dashboard \
    PROXY_BINARY=/usr/local/bin/3proxy DNS_CACHE_ENABLED=0
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends iproute2 curl ca-certificates dnsmasq-base \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 manager && useradd --uid 10001 --gid 10001 --no-create-home manager \
    && mkdir -p /app/data /run/ipv6-manager \
    && chown 0:10001 /run/ipv6-manager && chmod 0770 /run/ipv6-manager
WORKDIR /app
COPY requirements.txt /app/requirements.txt
COPY --from=python-builder /install/lib/python3.12/site-packages/ /usr/local/lib/python3.12/site-packages/
COPY --from=python-builder /install/bin/gunicorn /usr/local/bin/gunicorn
RUN python -m pip check \
    && python -c 'import aiohttp, flask, gunicorn, requests, telebot; print("RUNTIME_DEPENDENCIES=OK")'
COPY --from=builder /build/bin/3proxy /usr/local/bin/3proxy
COPY app.py ipv6_manager.py proxy_config.py state_store.py service.py rpc.py validation.py worker.py credentials.py network_inventory.py /app/
COPY resource_metrics.py host_control.py diagnostics.py passive_diagnostics.py /app/
COPY telegram_notify.py telegram_bot.py start.sh /app/
COPY templates/ /app/templates/
COPY static/ /app/static/
RUN chmod 0755 /app/start.sh /usr/local/bin/3proxy
USER 10001:10001
EXPOSE 7070
ENTRYPOINT ["/app/start.sh"]
