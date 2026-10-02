# Shared helpers for the run/demo/bench scripts. Source, do not execute.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN="$ROOT/.run"
mkdir -p "$RUN"
export PATH="$HOME/.cargo/bin:$PATH"
BIN="$ROOT/target/release"
ISSUER_URL="http://127.0.0.1:27180"
ISSUER_JAR="$ROOT/issuer/target/issuer-backoffice-0.1.0.jar"

build_all() {
  (cd "$ROOT" && CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-3}" cargo build --release -q)
  if [ ! -f "$ISSUER_JAR" ] || [ -n "$(find "$ROOT/issuer/src" "$ROOT/issuer/pom.xml" -newer "$ISSUER_JAR" 2>/dev/null | head -1)" ]; then
    (cd "$ROOT/issuer" && ./mvnw -q -T 2 -DskipTests package)
  fi
}

wait_http() { # url timeout_s
  local i=0
  until curl -sf -o /dev/null "$1"; do
    i=$((i + 1)); [ "$i" -gt $(( $2 * 4 )) ] && { echo "timeout waiting for $1" >&2; return 1; }
    sleep 0.25
  done
}

wait_port() { # port timeout_s
  local i=0
  until (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null; do
    i=$((i + 1)); [ "$i" -gt $(( $2 * 4 )) ] && { echo "timeout waiting for port $1" >&2; return 1; }
    sleep 0.25
  done
}

stop_pid() { # name [signal]
  local f="$RUN/$1.pid"
  if [ -f "$f" ]; then
    local pid; pid="$(cat "$f")"
    if kill -0 "$pid" 2>/dev/null; then
      kill -CONT "$pid" 2>/dev/null || true
      kill "-${2:-TERM}" "$pid" 2>/dev/null || true
      for _ in $(seq 1 80); do kill -0 "$pid" 2>/dev/null || break; sleep 0.25; done
      kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null || true
    fi
    rm -f "$f"
  fi
}

start_hsm() {
  "$BIN/hsm" serve --listen 127.0.0.1:27910 --lmk-file "$ROOT/config/lmk.test.hex" >"$RUN/hsm.log" 2>&1 &
  echo $! >"$RUN/hsm.pid"
  wait_port 27910 20
}

start_issuer() {
  ISSUER_DB_URL="jdbc:postgresql://127.0.0.1:${PG_PORT:-56543}/issuer" \
    java ${ISSUER_JAVA_OPTS:--Xms512m -Xmx1g} -jar "$ISSUER_JAR" >>"$RUN/issuer.log" 2>&1 &
  echo $! >"$RUN/issuer.pid"
  disown "$!" 2>/dev/null || true
  wait_http "$ISSUER_URL/internal/v1/health" 120
}

start_switch() { # [extra args]
  (cd "$ROOT" && exec "$BIN/card-switch" --config config/switch.toml "$@" >"$RUN/switch.log" 2>&1) &
  echo $! >"$RUN/switch.pid"
  wait_port 27583 20
}

stop_all() {
  stop_pid switch
  stop_pid issuer
  stop_pid hsm
}
