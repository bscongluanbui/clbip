#!/bin/bash
# Container lifecycle only. The Python worker is the sole network reconciler.
set -euo pipefail
cd /app
APP_ROLE=${APP_ROLE:-dashboard}
GUI_PORT=${GUI_PORT:-7070}
GUI_BIND=${GUI_BIND:-127.0.0.1}
children=()
finish() {
    trap - TERM INT EXIT
    for pid in "${children[@]}"; do kill -TERM "$pid" 2>/dev/null || true; done
    for pid in "${children[@]}"; do wait "$pid" 2>/dev/null || true; done
}
trap 'finish; exit 143' TERM
trap 'finish; exit 130' INT
trap finish EXIT
case "$APP_ROLE" in
  dashboard)
    python -c "from rpc import read_secret; import sys; bad=[n for n in ('SECRET_KEY','SERVICE_TOKEN') if len(read_secret(n)) < 32]; sys.exit('Missing/short deployment secrets: '+', '.join(bad) if bad else 0)"
    [[ "$GUI_PORT" =~ ^[0-9]+$ ]] && (( GUI_PORT >= 1024 && GUI_PORT <= 65535 ))
    # Gunicorn's optional control socket defaults to $HOME on a read-only root.
    gunicorn --no-control-socket --workers 1 --threads 8 --worker-class gthread \
      --bind "${GUI_BIND}:${GUI_PORT}" --timeout 300 --graceful-timeout 30 \
      --worker-tmp-dir /tmp --access-logfile - --error-logfile - app:app &
    children+=("$!")
    if [[ "${TELEGRAM_ENABLED:-0}" == "1" ]]; then
      python -u telegram_bot.py &
      children+=("$!")
    fi
    ;;
  worker)
    mkdir -p "${DATA_DIR:-/app/data}" "$(dirname "${WORKER_SOCKET:-/run/ipv6-manager/worker.sock}")"
    if [[ "${DNS_CACHE_ENABLED:-0}" == "1" ]]; then
      # High-port DNS does not replace host DNS or write /etc.
      dnsmasq --keep-in-foreground --conf-file=/dev/null --no-resolv \
        --no-hosts --bind-interfaces --listen-address=127.0.0.1 --port=5353 \
        --user=root --group=manager --cache-size=10000 \
        --server=1.1.1.1 --server=8.8.8.8 --pid-file=/tmp/dnsmasq.pid \
        --log-facility=- &
      children+=("$!")
    fi
    python -u worker.py &
    children+=("$!")
    ;;
  *) echo "Invalid APP_ROLE: $APP_ROLE" >&2; exit 64 ;;
esac
# Any child exit is actionable; stop siblings and let the orchestrator restart.
set +e
wait -n "${children[@]}"
status=$?
set -e
if (( status == 0 )); then status=1; fi
exit "$status"
