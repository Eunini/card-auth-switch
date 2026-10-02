#!/usr/bin/env bash
# Throwaway PostgreSQL for local runs (demo, benchmarks, PG test run).
# Uses Docker if available, otherwise local PostgreSQL binaries (initdb) in .run/pg.
#   scripts/pg-local.sh start|stop|status
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${PG_PORT:-56543}"
DATA="$ROOT/.run/pg"
CONTAINER=cas-issuer-pg

pg_bin() {
  if command -v pg_ctl >/dev/null 2>&1; then dirname "$(command -v pg_ctl)"; return; fi
  ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1
}

use_docker() { command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; }

case "${1:-start}" in
  start)
    if use_docker; then
      docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
      docker run -d --rm --name "$CONTAINER" -p "127.0.0.1:$PORT:5432" \
        -e POSTGRES_USER=issuer -e POSTGRES_PASSWORD=issuer -e POSTGRES_DB=issuer postgres:16-alpine >/dev/null
      for _ in $(seq 1 60); do docker exec "$CONTAINER" pg_isready -U issuer >/dev/null 2>&1 && break; sleep 0.5; done
      echo "postgres (docker) on 127.0.0.1:$PORT"
    else
      BIN="$(pg_bin)"
      [ -n "$BIN" ] || { echo "no docker and no PostgreSQL binaries found" >&2; exit 1; }
      if [ ! -f "$DATA/PG_VERSION" ]; then
        mkdir -p "$DATA"
        echo issuer > "$ROOT/.run/pgpass"
        "$BIN/initdb" -D "$DATA" -U issuer --pwfile="$ROOT/.run/pgpass" -A scram-sha-256 >/dev/null
      fi
      "$BIN/pg_ctl" -D "$DATA" -l "$ROOT/.run/pg.log" -o "-p $PORT -k $DATA -c listen_addresses=127.0.0.1 -c fsync=on -c synchronous_commit=on -c max_connections=200" -w start >/dev/null
      PGPASSWORD=issuer "$BIN/psql" -h 127.0.0.1 -p "$PORT" -U issuer -d postgres -tc \
        "SELECT 1 FROM pg_database WHERE datname='issuer'" | grep -q 1 || \
        PGPASSWORD=issuer "$BIN/createdb" -h 127.0.0.1 -p "$PORT" -U issuer issuer
      echo "postgres (local binaries $BIN) on 127.0.0.1:$PORT, data in $DATA"
    fi
    ;;
  reset)
    "$0" stop || true
    rm -rf "$DATA"
    "$0" start
    ;;
  stop)
    if use_docker; then docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; fi
    if [ -f "$DATA/postmaster.pid" ]; then "$(pg_bin)/pg_ctl" -D "$DATA" -m fast stop >/dev/null; fi
    echo "postgres stopped"
    ;;
  status)
    PGPASSWORD=issuer psql -h 127.0.0.1 -p "$PORT" -U issuer -d issuer -tc "select version()" ;;
esac
