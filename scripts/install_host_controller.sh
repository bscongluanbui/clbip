#!/usr/bin/env bash
set -euo pipefail
test "$(id -u)" = 0 || { echo 'Run this installer with sudo'; exit 1; }
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE="$(realpath -- "${1:-$HERE/../docker-compose.yml}")"
test -f "$COMPOSE"
case "$COMPOSE" in *$'\n'*|*'"'*|*'%'*|*'\\'*) echo 'Compose path invalid'; exit 1;; esac
command -v python3 >/dev/null
command -v docker >/dev/null
command -v systemctl >/dev/null
install -d -m 0755 /opt/clbip-host-controller
install -m 0755 "$HERE/host_controller.py" /opt/clbip-host-controller/host_controller.py
PYTHON="$(command -v python3)"
cat > /etc/systemd/system/clbip-host-controller.service <<UNIT
[Unit]
Description=CLBIP worker PID budget controller
After=docker.service
Requires=docker.service

[Service]
Type=simple
User=root
ExecStart=$PYTHON /opt/clbip-host-controller/host_controller.py --compose "$COMPOSE"
Restart=on-failure
RestartSec=2
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=read-only
ReadWritePaths=$(dirname -- "$COMPOSE")

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now clbip-host-controller.service
systemctl restart clbip-host-controller.service
systemctl is-active clbip-host-controller.service
echo 'HOST_PID_CONTROLLER_INSTALLED; existing proxy worker not restarted'
