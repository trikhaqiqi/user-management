#!/usr/bin/env bash
# Runs the three services as local background processes using .env.
#   scripts/run-local.sh start|stop|restart|status
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)
SERVICES=(auth-service core-service api-gateway)
RUN_DIR="$ROOT/tmp/run"
LOG_DIR="$ROOT/tmp/logs"
mkdir -p "$RUN_DIR" "$LOG_DIR"

[[ -f .env ]] || { echo ".env missing; run: make env" >&2; exit 1; }

start() {
  # Variables already set in the environment win over .env, so e.g.
  # `MAIL_DRIVER=file make run` works.
  local overrides; overrides=$(export -p)
  set -a; source "$ROOT/.env"; set +a
  eval "$overrides"
  echo "${MAIL_DRIVER:-smtp}" >"$RUN_DIR/mail_driver"
  for svc in "${SERVICES[@]}"; do
    if [[ -f "$RUN_DIR/$svc.pid" ]] && kill -0 "$(cat "$RUN_DIR/$svc.pid")" 2>/dev/null; then
      echo "$svc already running"; continue
    fi
    (cd "$ROOT/$svc" && go build -o "bin/$svc" .)
    (cd "$ROOT/$svc" && exec nohup "./bin/$svc" >>"$LOG_DIR/$svc.log" 2>&1) &
    echo $! >"$RUN_DIR/$svc.pid"
    sleep 0.5
    if ! kill -0 "$(cat "$RUN_DIR/$svc.pid")" 2>/dev/null; then
      echo "$svc failed to start:" >&2; tail -n 5 "$LOG_DIR/$svc.log" >&2; rm -f "$RUN_DIR/$svc.pid"; exit 1
    fi
    echo "started $svc (pid $(cat "$RUN_DIR/$svc.pid"), log tmp/logs/$svc.log)"
  done
  for i in $(seq 1 30); do
    curl -fsS "http://localhost:${GATEWAY_PORT:-8080}/health" >/dev/null 2>&1 && { echo "gateway ready on :${GATEWAY_PORT:-8080}"; return; }
    sleep 0.5
  done
  echo "gateway did not become healthy; check tmp/logs" >&2; exit 1
}

stop() {
  for svc in "${SERVICES[@]}"; do
    if [[ -f "$RUN_DIR/$svc.pid" ]]; then
      kill "$(cat "$RUN_DIR/$svc.pid")" 2>/dev/null && echo "stopped $svc" || true
      rm -f "$RUN_DIR/$svc.pid"
    fi
  done
}

status() {
  for svc in "${SERVICES[@]}"; do
    if [[ -f "$RUN_DIR/$svc.pid" ]] && kill -0 "$(cat "$RUN_DIR/$svc.pid")" 2>/dev/null; then
      echo "$svc: running (pid $(cat "$RUN_DIR/$svc.pid"))"
    else
      echo "$svc: stopped"
    fi
  done
}

case "${1:-start}" in
  start) start ;;
  stop) stop ;;
  restart) stop; sleep 1; start ;;
  status) status ;;
  *) echo "usage: $0 start|stop|restart|status" >&2; exit 2 ;;
esac
