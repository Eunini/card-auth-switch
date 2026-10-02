#!/usr/bin/env bash
# Start/stop the issuer back office against the local PostgreSQL.
#   scripts/issuer.sh start | stop | kill | hang | resume
source "$(dirname "$0")/common.sh"
case "${1:-start}" in
  start) start_issuer ;;
  stop) stop_pid issuer TERM ;;
  kill) stop_pid issuer KILL ;;  # simulate a crash
  hang) kill -STOP "$(cat "$RUN/issuer.pid")" ;;    # simulate a hung process / black-holed network
  resume) kill -CONT "$(cat "$RUN/issuer.pid")" ;;
esac
