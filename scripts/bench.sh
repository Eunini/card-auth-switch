#!/usr/bin/env bash
# Measure the stack on this machine. Results go to bench-results/.
#   1. HSM alone (PIN verify + ARQC verify/ARPC per iteration)
#   2. issuer internal authorize API alone (HTTP/JSON -> PostgreSQL)
#   3. end to end over TCP: terminal sim -> switch -> HSM + issuer (chip + PIN)
#   4. end to end with the issuer down: every transaction stood in (HSM + fsync'd SAF journal)
# Env: DURATION (s, default 30), WORKERS (default 64), CONNECTIONS (default 4), CARDS (default 2000)
source "$(dirname "$0")/common.sh"
trap 'stop_all' EXIT
OUT="${OUT_DIR:-$ROOT/bench-results}"
mkdir -p "$OUT"
DURATION="${DURATION:-30}"; WORKERS="${WORKERS:-64}"; CONNECTIONS="${CONNECTIONS:-4}"; CARDS="${CARDS:-2000}"
TS="$BIN/termsim --keys $ROOT/config/test-keys.toml"

build_all
"$ROOT/scripts/pg-local.sh" reset >/dev/null
rm -f "$RUN/stip-journal.log" "$RUN/card-snapshot.json" "$RUN/issuer.log"
start_issuer
start_hsm
$TS gen-cards --count "$CARDS" --out "$RUN/bench-cards.json" --import-url "$ISSUER_URL" >/dev/null

{
  echo "date_utc=$(date -u +%FT%TZ)"
  echo "cpu=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
  echo "vcpus=$(nproc)"
  echo "mem_gb=$(free -g | awk '/Mem:/{print $2}')"
  echo "loadavg_before=$(cut -d' ' -f1-3 /proc/loadavg)"
  echo "kernel=$(uname -r)"
  echo "rustc=$(rustc --version)"
  echo "java=$(java -version 2>&1 | head -1)"
  echo "postgres=$(PGPASSWORD=issuer psql -h 127.0.0.1 -p "${PG_PORT:-56543}" -U issuer -d issuer -tAc 'show server_version')"
  echo "duration_s=$DURATION workers=$WORKERS connections=$CONNECTIONS cards=$CARDS"
} >"$OUT/machine.txt"
cat "$OUT/machine.txt"

echo "== 1. HSM direct"
$TS bench-hsm --hsm 127.0.0.1:27910 --workers "$WORKERS" --duration-s 20 --out "$OUT/hsm-direct.json" >/dev/null
echo "== 2. issuer API direct"
$TS bench-issuer --issuer "$ISSUER_URL" --cards "$RUN/bench-cards.json" --workers "$WORKERS" --duration-s 20 \
  --out "$OUT/issuer-direct.json" >/dev/null

echo "== 3. end to end, issuer up"
start_switch --stats-out "$OUT/switch-stages-online.json"
$TS bench --switch 127.0.0.1:27583 --cards "$RUN/bench-cards.json" --connections "$CONNECTIONS" \
  --workers "$WORKERS" --duration-s "$DURATION" --out "$OUT/e2e-online.json" >/dev/null
stop_pid switch

echo "== 4. end to end, issuer down (stand-in)"
rm -f "$RUN/stip-journal.log"
start_switch --stats-out "$OUT/switch-stages-standin.json"
stop_pid issuer KILL
$TS bench --switch 127.0.0.1:27583 --cards "$RUN/bench-cards.json" --connections "$CONNECTIONS" \
  --workers "$WORKERS" --duration-s "$DURATION" --out "$OUT/e2e-standin.json" >/dev/null
stop_pid switch
echo "loadavg_after=$(cut -d' ' -f1-3 /proc/loadavg)" >>"$OUT/machine.txt"

python3 - "$OUT" <<'PY'
import json, sys, os
o = sys.argv[1]
j = lambda f: json.load(open(os.path.join(o, f)))
rows = [("HSM direct (PIN + ARQC per op)", j("hsm-direct.json"), "iterations_per_s"),
        ("Issuer API direct (HTTP+PostgreSQL)", j("issuer-direct.json"), "throughput_per_s"),
        ("End to end, issuer up", j("e2e-online.json"), "throughput_per_s"),
        ("End to end, stand-in", j("e2e-standin.json"), "throughput_per_s")]
print("| scenario | ops/s | p50 ms | p99 ms | max ms |\n|---|---:|---:|---:|---:|")
for name, r, k in rows:
    print(f"| {name} | {r[k]:.0f} | {r['p50_ms']:.2f} | {r['p99_ms']:.2f} | {r['max_ms']:.1f} |")
for f in ["switch-stages-online.json", "switch-stages-standin.json"]:
    print(f"\n{f}:")
    for s in j(f)["stages"]:
        print(f"  {s['stage']:<20} n={s['count']:<8} p50={s['p50_us']}us p99={s['p99_us']}us")
    print("  response codes:", j(f)["response_codes"])
PY
