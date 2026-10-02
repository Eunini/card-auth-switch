# Design notes

These are the decisions behind the code, written to be explained and defended in a design review.

## 1. ISO 8583 codec: the spec table drives everything

`crates/iso8583/src/spec.rs` holds a table of 128 `FieldSpec { content, length, encoding, prefix }`
entries. The codec in `message.rs` contains **no per-field logic**. It reads the MTI, reads the
bitmap(s), then for each set bit looks up the spec and decodes.

* **Content** is the character set: `n`, `a`, `an`, `ans`, `ns`, `z` (track data), `x+n`
  (signed amounts) and `b` (binary). It is validated on both encode and decode, so a decoded
  message is always re-encodable.
* **Length** is `Fixed(n)`, `LlVar(max)` or `LllVar(max)`. Prefixes count logical units
  (digits/characters, or bytes for `b`), not wire bytes.
* **Encoding** is ASCII, packed BCD (only for `n`/`z`), or binary/hex for `b`. Odd-length
  numerics in BCD are left-padded with `0`. Track data is right-padded with `F`, which is the
  common convention for PAN and track 2. The `=` separator in track 2 becomes nibble `D`.
* **Profiles.** A network or terminal dialect is a different table. The built-in profiles are
  1987 ASCII (binary bitmap), 1987 BCD (BCD MTI, BCD prefixes), 1987 text (hex bitmaps and hex
  binary fields) and a partial 1993 profile. `Spec::validate()` rejects impossible combinations
  such as a BCD `an` field.
* **Values are stored in logical form** (ASCII digits, raw bytes). Masking for logs
  (`Message::describe`) is part of the model: PAN shown as first 6 / last 4, track 2 masked, PIN
  block redacted, F55 expanded into tags.
* **Untrusted input.** All reads go through a bounds-checked `Reader`, so every failure is a
  typed `Error`. Proptest checks round trips for all profiles, arbitrary bytes, plausible headers
  (MTI + random bitmap + junk) and single-byte corruptions/truncations of valid messages. A
  tertiary bitmap (bit 65 of the secondary bitmap) is rejected rather than silently
  misinterpreted.

**Differences in 1993 that the partial profile shows:**

| Field | 1987 | 1993 |
|---|---|---|
| MTI version digit | `0` | `1` |
| F12 | `hhmmss` | `YYMMDDhhmmss` |
| F22 | `n3` POS entry mode | `an12` POS data code |
| F24 | NII | function code |
| F25 | POS condition code | `n4` message reason code |
| F39 | `an2` response code | `n3` action code |
| F43 | fixed `ans40` | LLVAR |
| Original data elements | F90 (fixed `n42`) | F56 (LLVAR); F90 reserved |

## 2. Authorization pipeline and response-code precedence

The order is deliberate. Cheap checks that do not need secrets come first, then cryptography,
then money:

1. **Format.** Mandatory fields are F3, F4, F49 and the key fields. A failure here is 30.
2. **Card.** Checks run in this order:
   * Luhn
   * card lookup by HMAC(PAN): 14 if unknown
   * status: 41 lost, 43 stolen, 62 blocked
   * currency: 12 on mismatch
   * expiry: 54
3. **Cardholder.** The PIN-try counter is checked first (75), then the HSM verifies the PVV
   (55). Cash requires a PIN.
4. **Card authentication.**
   * **ARQC (chip).** The checks are, in order:
     * the cryptogram type in 9F27 must be ARQC;
     * 9F02 must equal F4, because the cryptogram has to cover the amount actually being
       authorised;
     * the CVN in the IAD must match the card profile;
     * the HSM verifies the cryptogram;
     * only then is the ATC checked against the high-water mark (82 on replay). The ATC check
       comes after cryptographic verification so that a forged message cannot advance the
       counter.
   * **CVV (magstripe).** The CVV is checked from track 2.
5. **Switch-side limits.** These are per-transaction (61), daily count (65) and daily cash (61).
   They are *reserved* atomically before the issuer call and released on decline, so concurrent
   requests on one card cannot overshoot.
6. **Issuer open-to-buy, or stand-in.**
7. **ARPC.** The ARPC is computed in the same HSM call as ARQC verification, using the
   "approve" parameters (one round trip in the common case). A decline needs a second call with
   the decline ARC/CSU. A decline is still issuer-authenticated, so the card can trust it.

## 3. EMV ARQC verification, step by step (CVN 18)

1. **ICC master key, option A** (EMV Book 2, A1.4.1).
   `Y = rightmost 16 digits of PAN||PSN`, then `MK = 3DES_IMK(Y) || 3DES_IMK(Y xor FF…FF)`,
   with odd parity applied. Option B (SHA-1 plus decimalization) is used for PANs longer than 16
   digits. CVN 18 cards use option B, which is identical to option A for 16-digit PANs.
2. **Session key, EMV common session key derivation** (A1.3.1).
   `R = ATC || 00 00 00 00 00 00`, then
   `SK = 3DES_MK(R with R[2]=F0) || 3DES_MK(R with R[2]=0F)`, with parity applied.
   CVN 10 has no session key: MK-AC is used directly.
3. **Data.** The data is
   9F02 ‖ 9F03 ‖ 9F1A ‖ 95 ‖ 5F2A ‖ 9A ‖ 9C ‖ 9F37 ‖ 82 ‖ 9F36 ‖ (CVN 18: full 9F10 IAD;
   CVN 10: the 4-byte CVR from IAD bytes 3..7).
4. **MAC.** ISO/IEC 9797-1 MAC algorithm 3 (single-DES CBC with K1, then decrypt K2 / encrypt K1
   on the last block). CVN 18 uses padding method 2 (`80 00…`). CVN 10 uses method 1 (zeros).
5. **ARPC.**
   * Method 1 (CVN 10): `3DES_SK(ARQC xor (ARC || 00*6))`, where tag 91 = ARPC ‖ ARC.
   * Method 2 (CVN 18): the first 4 bytes of the MAC alg. 3 over `ARQC ‖ CSU ‖ prop data`,
     where tag 91 = ARPC ‖ CSU. The CSU here is simplified: only the "issuer approves" bit is
     set.

Every step is pinned to published vectors and to a 60-case differential test against pyemv and
psec (see the README). The block cipher is RustCrypto's `des`. Only the constructions are written
here.

## 4. Key hierarchy (simulated HSM)

```
LMK (AES-256, inside HSM only)
 ├─ ZMK  [K0]  zone master key: imports keys from partners (ImportKey: 3DES-ECB under ZMK)
 ├─ ZPK  [P0]  zone PIN key: PIN blocks acquirer <-> switch (ISO 9564 format 0)
 ├─ PVK  [V2]  PIN verification key: Visa PVV (and IBM 3624 offset)
 ├─ CVK  [C0]  CVV / iCVV
 └─ IMK-AC [E0] issuer master key -> per-card MK-AC (derived on the fly) -> per-ATC session key
```

* Key blocks bind usage cryptographically through the AEAD associated data. Using a key outside
  its usage is a typed `KeyUsage` error.
* The switch config contains only key blocks. The switch process cannot unwrap them.
* `FormKeyFromComponents` (XOR of clear components) is the key-ceremony path and needs
  "authorized state".
* KCVs are the standard 3-byte 3DES encryption of zeros.

## 5. Why stand-in (STIP), and how it stays safe

Authorizations have a hard end-to-end budget: terminals and networks time out within seconds. If
the issuer's back office is slow or down, declining everything means stranded cardholders and
lost sales. Networks therefore offer stand-in processing, and issuers set its limits.

* **Deadline.** The issuer call has a 250 ms timeout. Two consecutive outages open a **circuit
  breaker**, so later requests go straight to stand-in instead of each one paying the deadline.
  A health probe every 250 ms closes the circuit. Half-open lets one live probe through per
  window.
* **What still runs in stand-in.** PIN, ARQC, CVV, status, expiry, ATC and velocity checks all
  still run (HSM and card cache are local). Only the balance check is replaced by
  **stand-in limits**: per transaction, and cumulative per card per day. These are reserved
  atomically.
* **Card data in stand-in.** The card cache is a periodically refreshed snapshot from the issuer,
  persisted to disk, so a switch restart during an issuer outage still has card data.
* **Durability.** The `0120` advice is appended to the SAF journal and **fsynced before** the
  approval is sent. If the switch crashes afterwards, the advice survives. Concurrent enqueues are
  group-committed (one `fdatasync` per batch). A torn final line from a crash is truncated on
  open. Acks are appended without fsync: losing one only causes a re-delivery, which the issuer
  de-duplicates.
* **Ordering.** Replay is FIFO and stops at the first outage. While anything is queued, new
  reversals and advices are queued behind it, so a reversal can never reach the issuer before the
  advice for the authorization it reverses.
* **The timeout race.** The switch gave up waiting, but the issuer *did* process the request
  late. When the advice arrives, the issuer finds the same `auth_ref`:
  * If both approved, it keeps **one** hold and adopts the stand-in approval code, because that
    is what the merchant will present in clearing.
  * If the issuer declined but stand-in approved, the advice wins. The cardholder has the goods,
    so the hold is forced, even into overdraft, and flagged.

  The demo provokes this race for real with `SIGSTOP`/`SIGCONT`.

## 6. Reversal matching keys and idempotency

* **`auth_ref` = terminal id + original local date (MMDD from F7) + original STAN + RRN.** The
  acquirer's STAN repeats daily and per terminal. The RRN alone is not guaranteed unique across
  acquirers. Together they identify the original in the acquirer's own terms.
* **The key is deterministic.** It is built from F41 + F90 (original STAN, original F7) + F37,
  so a reversal can be matched **even after a switch restart**. The switch's in-memory
  authorization log is only a fast path.
* **Idempotency at every layer:**
  * Switch duplicate cache keyed by message class + `auth_ref`. A retransmission replays the
    stored response. A duplicate still in flight gets 94.
  * Switch reversal log keyed by `reversal_ref` = `auth_ref` + replacement amount. A 0401 or
    0421 repeat returns the stored result and does not call the issuer.
  * Issuer: `authorizations.auth_ref` is UNIQUE and checked after taking the account row lock,
    `reversals.reversal_ref` is the primary key, `advices.advice_id` is the primary key, and
    `journal_entries.reference` is UNIQUE.
  * Clearing: `clearing_files.file_id` and `clearing_records.record_id` are UNIQUE.
* **Reversal before original.** If a reversal arrives for an unknown original, the switch records
  a tombstone. An original arriving later with the same key is declined, so a hold is never
  placed for a transaction the terminal already cancelled.
* **Partial reversal.** F95 carries the new amount. The hold shrinks to `replacement - cleared`.

## 7. Issuer back office

* **Double-entry ledger.**
  * Every money movement is one immutable journal entry whose debit legs equal its credit legs.
    It is keyed by a business reference, which makes posting idempotent.
  * Balances are materialized on the normal side of each account in the same transaction. The
    trial balance endpoint recomputes them from postings and checks both "debits = credits" and
    "materialized = derived".
  * Ledger account rows are updated in id order to avoid deadlocks.
* **Holds are not ledger entries.** An authorization changes `held_minor`, not the ledger:
  `available = ledger balance + credit limit - held`. Money moves only at clearing. This is how
  issuers separate "authorized" from "posted".
* **Concurrency.** Every hold change takes `SELECT … FOR UPDATE` on the card account row, so one
  account is serialized and different accounts run in parallel. The 16-thread test proves there
  is no overselling.
* **Hold lifetimes.** Holds expire after 7 days, or 30 days for lodging, car rental and cruise
  MCCs. Incremental authorizations grow the original hold and extend its expiry. A late
  presentment against an expired hold still matches (`MATCHED_EXPIRED_HOLD`).
* **Clearing match order.**
  1. Same card + approval code + RRN.
  2. Same card + approval code + amount within MCC tolerance (20% for restaurants and taxis,
     otherwise none) + authorization within 30 days before the transaction date.
  3. Otherwise **force post**: we still owe the network.

  An unknown card is posted to a suspense account. Multiple presentments (`seq/count`) clear the
  hold progressively, and the final one releases the remainder. Amounts over tolerance post but
  are flagged.
* **Disputes.** These are an explicit state machine (`DisputeState.next()`). Every transition is
  an audit row, and every money movement is a ledger entry referenced by dispute id.
  * Opening gives a provisional credit (Dr DISPUTE_RECEIVABLE / Cr CARDHOLDER).
  * Reason codes carry time limits and the evidence type required before a chargeback can be
    sent.
  * A deadline job closes disputes: expired window → write-off, no representment → won,
    no pre-arbitration → lost and cardholder rebilled.

## 8. Failure modes

| Failure | Behaviour |
|---|---|
| Issuer slow / hung | 250 ms deadline, then stand-in. Circuit opens after 2 failures. Late processing is reconciled by `auth_ref`. |
| Issuer down (connection refused) | Immediate stand-in. Advices stored with fsync and replayed when health returns. |
| Issuer returns 4xx (contract error) | Decline 05. Not treated as an outage, so a bug cannot trigger mass stand-in. SAF entries rejected with 4xx are dead-lettered (logged and acked) so one poison message cannot block the queue. |
| HSM down / timeout | 96 (system malfunction). Never approve without cryptographic verification. |
| Switch crash after a stand-in approval | The advice was fsynced before the response, so it is replayed on restart. |
| Switch crash during a journal write | The torn tail line is truncated on open. |
| Duplicate / repeated messages | Replayed responses. The issuer de-duplicates by reference anyway. |
| Malformed message | RC 30 if the MTI is readable, otherwise the frame is dropped. Framing errors close the connection. |
| Idle acquirer connection | Closed after `idle_timeout_secs`. In-flight requests are bounded per connection by a semaphore. |
| Issuer DB contention | Row locks per account. Clearing locks account, then ledger rows, in a fixed order. |

## 9. What I would do next for production

* Persist the switch's PIN-try counters and ATC high-water marks, or move them to the issuer's
  card record.
* Run an active/active switch pair with a replicated SAF.
* Add message MACs and dynamic key exchange (0800 key change).
* Use DUKPT at the terminal edge with ZPK translation, and TLS/mTLS on internal links.
* Add metrics export (Prometheus) instead of the shutdown stats dump.
* Handle network-specific dialects as additional spec tables.
