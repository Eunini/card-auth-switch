# Clearing file format (CASCLR v1)

This is a simple pipe-delimited text format, modelled on the record types that real network
clearing files carry: first presentment, chargeback, and second presentment (representment).
It is **not** Visa BASE II or Mastercard IPM. It exists so that the matching and dispute logic
can be exercised end to end.

```
HDR|CASCLR|1|<fileId>|<processingDate YYYYMMDD>|<sender>
PRES|<recordId>|<ARN>|<PAN>|<approvalCode>|<RRN>|<terminalId>|<txnDate YYYYMMDD>|<amountMinor>|<currency>|<MCC>|<merchant>|<seq>|<count>
CHBK|<recordId>|<ARN>|<disputeRef>|<amountMinor>|<currency>|<reasonCode>
REPR|<recordId>|<ARN>|<disputeRef>|<amountMinor>|<currency>|<reason text>
TRL|<recordCount>|<hashTotalMinor>
```

| Field | Rule |
|---|---|
| fileId | Unique per sender. Re-sending a file is rejected (409), so nothing is posted twice. |
| recordId | Globally unique. A record seen before is reported `DUPLICATE_RECORD` and skipped. |
| ARN | Acquirer Reference Number, 23 digits: `7` + acquirer BIN (6) + YDDD + sequence (11) + check digit. Links a presentment to its later chargeback and representment. |
| PAN | Full PAN. It is converted to an HMAC reference on ingest and never stored. |
| approvalCode, RRN | Used for matching to the authorization (F38, F37). |
| amountMinor | Positive integer in minor units. |
| currency | ISO 4217 numeric. |
| seq / count | Multiple presentments for one authorization (split shipment). The final one (`seq == count`) releases any remaining hold. |
| disputeRef | `DSP-<id>`, as sent in the issuer's outgoing chargeback file. |
| TRL | Must match the record count and the sum of amounts, otherwise the whole file is rejected with the line number. |

The issuer's outgoing chargeback file (`GET /api/v1/clearing/outgoing`) uses the same envelope
with `CHBK` records.

## Outcomes per record

| Outcome | Meaning |
|---|---|
| `MATCHED` | The presentment matched an authorization. The amount is posted (Dr cardholder / Cr network settlement) and the hold is reduced or released. |
| `MATCHED_OVER_TOLERANCE` | Matched on approval code + RRN, but the amount is above the authorized amount plus the MCC tolerance. Posted and flagged. |
| `MATCHED_EXPIRED_HOLD` | The hold had already expired. Posted. |
| `FORCE_POST` | No matching authorization. Posted to the cardholder anyway. |
| `UNKNOWN_CARD` | Posted to clearing suspense for investigation. |
| `CHARGEBACK_SETTLED` | Dispute moved from CHARGEBACK_SENT. Dr network settlement / Cr dispute receivable. |
| `REPRESENTED` | Dispute moved from CHARGEBACK_SETTLED. Dr dispute receivable / Cr network settlement. |
| `UNMATCHED_*` | The dispute was not found, was in the wrong state, the amount was wrong, or the record was late. Not posted. |
| `DUPLICATE_RECORD` | Skipped. |
