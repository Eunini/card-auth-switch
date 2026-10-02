//! Test card generation (plays the issuer's card personalisation bureau).

use crate::keys::TestKeys;
use cardcrypto::{cvv, luhn, pin};
use hmac::{Hmac, Mac};
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Fictional BIN in the ISO/IEC 7812 "national use" range (MII 9) so no
/// generated PAN can belong to a real card.
pub const TEST_BIN: &str = "999001";

/// Everything the *terminal side* knows about a test card: the physical
/// card's data and the cardholder's PIN.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardSecret {
    pub name: String,
    pub pan: String,
    pub pin: String,
    pub expiry: String,
    pub service_code: String,
    pub psn: String,
    pub cvn: u8,
    pub pvv: String,
    pub cvv: String,
    pub icvv: String,
    pub atc: u16,
}

impl CardSecret {
    /// Track 2: PAN=YYMM SVC PVKI PVV CVV + filler. Chip "track 2
    /// equivalent data" carries the iCVV (CVV computed with service code
    /// 999) instead of the magstripe CVV, so skimmed chip data cannot be
    /// replayed as a magstripe transaction.
    pub fn track2(&self, pvki: u8, chip_equivalent: bool) -> String {
        let cvv = if chip_equivalent {
            &self.icvv
        } else {
            &self.cvv
        };
        format!(
            "{}={}{}{}{}{}00000",
            self.pan, self.expiry, self.service_code, pvki, self.pvv, cvv
        )
    }
}

/// What the issuer back office stores: no PAN, no PIN.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerCardRecord {
    pub pan_ref: String,
    pub last4: String,
    pub expiry: String,
    pub status: String,
    pub pvv: String,
    pub pvki: u8,
    pub service_code: String,
    pub psn: String,
    pub cvn: u8,
    pub currency: String,
    pub holder_name: String,
    pub credit_limit_minor: i64,
    pub opening_balance_minor: i64,
    pub per_txn_limit_minor: i64,
    pub daily_cash_limit_minor: i64,
    pub daily_txn_count_limit: u32,
}

pub fn pan_ref(hmac_key_hex: &str, pan: &str) -> String {
    let key = hex::decode(hmac_key_hex).expect("hmac key hex");
    let mut m = Hmac::<Sha256>::new_from_slice(&key).expect("hmac");
    m.update(pan.as_bytes());
    hex::encode(&m.finalize().into_bytes()[..16])
}

#[derive(Debug, Clone)]
pub struct CardSpec {
    pub name: String,
    pub cvn: u8,
    pub status: String,
    pub opening_balance_minor: i64,
    pub credit_limit_minor: i64,
    pub per_txn_limit_minor: i64,
    pub daily_cash_limit_minor: i64,
    pub daily_txn_count_limit: u32,
    pub expiry: String,
}

impl CardSpec {
    pub fn standard(name: &str, cvn: u8, balance: i64) -> Self {
        Self {
            name: name.into(),
            cvn,
            status: "ACTIVE".into(),
            opening_balance_minor: balance,
            credit_limit_minor: 0,
            per_txn_limit_minor: 500_000,
            daily_cash_limit_minor: 100_000,
            daily_txn_count_limit: 20,
            expiry: "2912".into(),
        }
    }
}

pub fn issue(
    keys: &TestKeys,
    seq: u64,
    spec: &CardSpec,
    rng: &mut impl Rng,
) -> anyhow::Result<(CardSecret, IssuerCardRecord)> {
    let body = format!("{TEST_BIN}{seq:09}");
    let pan = format!("{body}{}", luhn::check_digit(&body).expect("digits"));
    let pin_value = format!("{:04}", rng.gen_range(0..10_000));
    let pvk = TestKeys::key(&keys.pvk);
    let cvk = TestKeys::key(&keys.cvk);
    let pvv = pin::visa_pvv(&pvk, keys.pvki, &pin_value, &pan)?;
    let service_code = "201".to_string();
    let cvv1 = cvv::cvv(&cvk, &pan, &spec.expiry, &service_code)?;
    let icvv = cvv::cvv(&cvk, &pan, &spec.expiry, "999")?;
    let secret = CardSecret {
        name: spec.name.clone(),
        pan: pan.clone(),
        pin: pin_value,
        expiry: spec.expiry.clone(),
        service_code: service_code.clone(),
        psn: "00".into(),
        cvn: spec.cvn,
        pvv: pvv.clone(),
        cvv: cvv1,
        icvv,
        atc: 0,
    };
    let record = IssuerCardRecord {
        pan_ref: pan_ref(&keys.pan_hmac, &pan),
        last4: pan[pan.len() - 4..].to_string(),
        expiry: spec.expiry.clone(),
        status: spec.status.clone(),
        pvv,
        pvki: keys.pvki,
        service_code,
        psn: "00".into(),
        cvn: spec.cvn,
        currency: "840".into(),
        holder_name: spec.name.clone(),
        credit_limit_minor: spec.credit_limit_minor,
        opening_balance_minor: spec.opening_balance_minor,
        per_txn_limit_minor: spec.per_txn_limit_minor,
        daily_cash_limit_minor: spec.daily_cash_limit_minor,
        daily_txn_count_limit: spec.daily_txn_count_limit,
    };
    Ok((secret, record))
}

/// Bulk cards for load tests: big balances and limits so the benchmark
/// measures the authorization path, not declines.
pub fn generate_bulk(
    keys: &TestKeys,
    count: usize,
    start_seq: u64,
    seed: u64,
) -> anyhow::Result<Vec<(CardSecret, IssuerCardRecord)>> {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    (0..count)
        .map(|i| {
            let mut spec = CardSpec::standard(
                &format!("Load Test {i:05}"),
                if i % 2 == 0 { 18 } else { 10 },
                1_000_000_000,
            );
            spec.per_txn_limit_minor = 10_000_000;
            spec.daily_txn_count_limit = 1_000_000;
            spec.daily_cash_limit_minor = 1_000_000_000;
            issue(keys, start_seq + i as u64, &spec, &mut rng)
        })
        .collect()
}
