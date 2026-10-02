#!/usr/bin/env bash
# Bring the whole stack up or down: PostgreSQL, issuer back office, simulated HSM, switch.
#   scripts/stack.sh up | down
source "$(dirname "$0")/common.sh"
case "${1:-up}" in
  up)
    build_all
    "$ROOT/scripts/pg-local.sh" start
    start_issuer
    start_hsm
    start_switch
    echo "issuer $ISSUER_URL | HSM 127.0.0.1:27910 | switch 127.0.0.1:27583 | logs in .run/"
    ;;
  down)
    stop_all
    "$ROOT/scripts/pg-local.sh" stop
    ;;
esac
