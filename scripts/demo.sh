#!/usr/bin/env bash
# Scripted end-to-end scenario on a fresh database. Writes docs/demo-transcript.txt.
#   sign-on, chip+PIN purchases, wrong PIN, forged ARQC, insufficient funds,
#   reversal (+repeat), partial reversal, issuer outage -> stand-in ->
#   recovery and advice replay, clearing file -> postings, chargeback.
source "$(dirname "$0")/common.sh"
trap 'stop_all' EXIT

build_all
"$ROOT/scripts/pg-local.sh" reset >/dev/null
rm -f "$RUN/stip-journal.log" "$RUN/card-snapshot.json" "$RUN/issuer.log"
start_issuer
start_hsm
"$BIN/termsim" --keys "$ROOT/config/test-keys.toml" demo-setup --issuer "$ISSUER_URL" --out "$RUN/demo-cards.json"
start_switch

"$BIN/termsim" --keys "$ROOT/config/test-keys.toml" demo \
  --switch 127.0.0.1:27583 --issuer "$ISSUER_URL" --cards "$RUN/demo-cards.json" \
  --transcript "${TRANSCRIPT:-$ROOT/docs/demo-transcript.txt}" \
  --issuer-ctl "$ROOT/scripts/issuer.sh"
