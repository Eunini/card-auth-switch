//! Writer for the clearing file format documented in docs/clearing-format.md.

use chrono::NaiveDate;

#[derive(Debug, Clone)]
pub enum Record {
    Presentment {
        record_id: String,
        arn: String,
        pan: String,
        auth_code: String,
        rrn: String,
        terminal_id: String,
        txn_date: NaiveDate,
        amount_minor: i64,
        currency: String,
        mcc: String,
        merchant: String,
        seq: u32,
        count: u32,
    },
    /// Network confirmation that the issuer's chargeback was accepted and settled.
    Chargeback {
        record_id: String,
        arn: String,
        dispute_ref: String,
        amount_minor: i64,
        currency: String,
        reason_code: String,
    },
    /// Acquirer's second presentment (representment) after a chargeback.
    Representment {
        record_id: String,
        arn: String,
        dispute_ref: String,
        amount_minor: i64,
        currency: String,
        reason: String,
    },
}

impl Record {
    fn amount(&self) -> i64 {
        match self {
            Record::Presentment { amount_minor, .. }
            | Record::Chargeback { amount_minor, .. }
            | Record::Representment { amount_minor, .. } => *amount_minor,
        }
    }

    fn line(&self) -> String {
        match self {
            Record::Presentment {
                record_id, arn, pan, auth_code, rrn, terminal_id, txn_date, amount_minor,
                currency, mcc, merchant, seq, count,
            } => format!(
                "PRES|{record_id}|{arn}|{pan}|{auth_code}|{rrn}|{terminal_id}|{}|{amount_minor}|{currency}|{mcc}|{merchant}|{seq}|{count}",
                txn_date.format("%Y%m%d")
            ),
            Record::Chargeback { record_id, arn, dispute_ref, amount_minor, currency, reason_code } => {
                format!("CHBK|{record_id}|{arn}|{dispute_ref}|{amount_minor}|{currency}|{reason_code}")
            }
            Record::Representment { record_id, arn, dispute_ref, amount_minor, currency, reason } => {
                format!("REPR|{record_id}|{arn}|{dispute_ref}|{amount_minor}|{currency}|{reason}")
            }
        }
    }
}

/// Acquirer Reference Number: 23 digits, format indicator 7 + 6-digit
/// acquirer BIN + YDDD + 11-digit sequence + check digit.
pub fn arn(acquirer_bin: &str, date: NaiveDate, seq: u64) -> String {
    use chrono::Datelike;
    let body = format!(
        "7{acquirer_bin:0>6}{}{:03}{seq:011}",
        date.year() % 10,
        date.ordinal()
    );
    format!(
        "{body}{}",
        cardcrypto::luhn::check_digit(&body).unwrap_or(0)
    )
}

pub fn write_file(
    file_id: &str,
    processing_date: NaiveDate,
    sender: &str,
    records: &[Record],
) -> String {
    let mut s = format!(
        "HDR|CASCLR|1|{file_id}|{}|{sender}\n",
        processing_date.format("%Y%m%d")
    );
    for r in records {
        s.push_str(&r.line());
        s.push('\n');
    }
    let total: i64 = records.iter().map(Record::amount).sum();
    s.push_str(&format!("TRL|{}|{total}\n", records.len()));
    s
}
