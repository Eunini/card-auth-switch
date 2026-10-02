//! Message processing: network management, authorization (0100/0200),
//! advices (0120/0220), reversals (0400/0420), stand-in processing and
//! store-and-forward replay.

use crate::cards::{pan_ref, CardCache, CardProfile};
use crate::circuit::Circuit;
use crate::config::Config;
use crate::issuer::*;
use crate::journal::{Journal, SafItem};
use crate::rc;
use crate::stats::Stats;
use crate::store::{AuthRecord, DupState, Store};
use cardcrypto::emv::{ArqcData, Cvn};
use chrono::{Datelike, Utc};
use dashmap::mapref::entry::Entry;
use hsm::client::{ClientError, HsmClient};
use hsm::proto::{ArpcMethod, Command, HsmError, Reply};
use iso8583::tlv::{self, Tlv};
use iso8583::{Message, Spec};
use rand::Rng;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Fields copied from an authorization request into its response.
const ECHO_AUTH: &[u8] = &[2, 3, 4, 7, 11, 12, 13, 22, 32, 37, 41, 42, 49];
const ECHO_REVERSAL: &[u8] = &[2, 3, 4, 7, 11, 32, 37, 41, 42, 49, 90, 95];
const ECHO_NETWORK: &[u8] = &[7, 11, 70];

/// PIN tries allowed before the card is PIN-blocked.
pub const MAX_PIN_TRIES: u32 = 3;

/// Per-connection state.
#[derive(Default)]
pub struct Session {
    pub signed_on: AtomicBool,
}

/// Reversal/duplicate matching key: terminal, local date (MMDD of the
/// original transmission date-time), STAN and RRN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchKey {
    pub terminal: String,
    pub mmdd: String,
    pub stan: String,
    pub rrn: String,
}

impl MatchKey {
    pub fn auth_ref(&self) -> String {
        format!("{}-{}-{}-{}", self.terminal, self.mmdd, self.stan, self.rrn)
    }

    pub fn from_request(m: &Message) -> Option<MatchKey> {
        Some(MatchKey {
            terminal: m.get_str(41)?.trim().to_string(),
            mmdd: m.get_str(7)?.get(0..4)?.to_string(),
            stan: m.get_str(11)?.to_string(),
            rrn: m.get_str(37)?.trim().to_string(),
        })
    }

    /// From a reversal: original STAN and date come from field 90
    /// (MTI 4 | STAN 6 | transmission date-time 10 | acquirer 11 | forwarder 11).
    pub fn from_reversal(m: &Message) -> Option<MatchKey> {
        let f90 = m.get_str(90)?;
        Some(MatchKey {
            terminal: m.get_str(41)?.trim().to_string(),
            mmdd: f90.get(10..14)?.to_string(),
            stan: f90.get(4..10)?.to_string(),
            rrn: m.get_str(37)?.trim().to_string(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Track2 {
    pub pan: String,
    pub expiry: String,
    pub service_code: String,
    pub discretionary: String,
}

/// `PAN=YYMM SSS discretionary`; the cards issued here use the common
/// layout PVKI(1) PVV(4) CVV(3) at the start of the discretionary data.
pub fn parse_track2(t: &str) -> Option<Track2> {
    let (pan, rest) = t.split_once('=')?;
    Some(Track2 {
        pan: pan.to_string(),
        expiry: rest.get(0..4)?.to_string(),
        service_code: rest.get(4..7)?.to_string(),
        discretionary: rest.get(7..)?.to_string(),
    })
}

#[derive(Debug)]
struct Decision {
    rc: &'static str,
    auth_code: Option<String>,
    stand_in: bool,
    tag91: Option<Vec<u8>>,
}

impl Decision {
    fn decline(rc: &'static str) -> Self {
        Decision {
            rc,
            auth_code: None,
            stand_in: false,
            tag91: None,
        }
    }
}

/// Chip context kept between ARQC verification and ARPC generation.
struct ChipCtx {
    cvn: Cvn,
    pan: String,
    psn: String,
    atc: [u8; 2],
    data: Vec<u8>,
    arqc: [u8; 8],
    approval_tag91: Option<Vec<u8>>,
}

pub struct Switch {
    pub cfg: Config,
    pub spec: Spec,
    pub hsm: Arc<HsmClient>,
    pub issuer: Arc<dyn IssuerApi>,
    pub cards: Arc<CardCache>,
    pub circuit: Circuit,
    pub journal: Arc<Journal>,
    pub store: Store,
    pub stats: Stats,
    pan_key: Vec<u8>,
}

fn static_rc(s: &str) -> &'static str {
    match s {
        "00" => rc::APPROVED,
        "05" => rc::DO_NOT_HONOR,
        "12" => rc::INVALID_TRANSACTION,
        "13" => rc::INVALID_AMOUNT,
        "14" => rc::INVALID_CARD,
        "41" => rc::LOST_CARD,
        "43" => rc::STOLEN_CARD,
        "51" => rc::INSUFFICIENT_FUNDS,
        "54" => rc::EXPIRED_CARD,
        "57" => "57",
        "61" => rc::EXCEEDS_AMOUNT_LIMIT,
        "62" => rc::RESTRICTED_CARD,
        "65" => rc::EXCEEDS_FREQUENCY_LIMIT,
        "91" => rc::ISSUER_UNAVAILABLE,
        "96" => rc::SYSTEM_MALFUNCTION,
        _ => rc::DO_NOT_HONOR,
    }
}

fn bcd_amount(minor: i64) -> [u8; 6] {
    let s = format!("{:012}", minor.clamp(0, 999_999_999_999));
    let mut out = [0u8; 6];
    for (i, p) in s.as_bytes().chunks(2).enumerate() {
        out[i] = ((p[0] - b'0') << 4) | (p[1] - b'0');
    }
    out
}

fn fixed<const N: usize>(list: &[Tlv], tag: u32) -> Option<[u8; N]> {
    tlv::find(list, tag)?.try_into().ok()
}

impl Switch {
    pub fn new(
        cfg: Config,
        hsm: Arc<HsmClient>,
        issuer: Arc<dyn IssuerApi>,
        cards: Arc<CardCache>,
        journal: Arc<Journal>,
    ) -> anyhow::Result<Self> {
        let pan_key = hex::decode(&cfg.pan_hmac_key)?;
        let circuit = Circuit::new(
            cfg.circuit.failure_threshold,
            Duration::from_millis(cfg.circuit.open_ms),
        );
        Ok(Self {
            cfg,
            spec: Spec::v1987_ascii(),
            hsm,
            issuer,
            cards,
            circuit,
            journal,
            store: Store::default(),
            stats: Stats::default(),
            pan_key,
        })
    }

    pub fn pan_ref(&self, pan: &str) -> String {
        pan_ref(&self.pan_key, pan)
    }

    /// Entry point for one inbound message. Returns the response, if any.
    pub async fn handle(&self, msg: Message, session: &Session) -> Option<Message> {
        let mti = msg.mti;
        if !mti.is_request_or_advice() {
            tracing::debug!(%mti, "ignoring unsolicited response");
            return None;
        }
        if mti.class() == 8 {
            return Some(self.network(&msg, session));
        }
        if !session.signed_on.load(Ordering::Acquire) {
            let mut r = msg.response_template(ECHO_AUTH)?;
            r.set(39, rc::NOT_PERMITTED_TO_TERMINAL);
            return Some(r);
        }
        match (mti.class(), mti.function()) {
            (1 | 2, 0) => Some(self.authorize(msg).await),
            (1 | 2, 2) => Some(self.acquirer_advice(msg).await),
            (4, 0 | 2) => Some(self.reversal(msg).await),
            _ => {
                let mut r = msg.response_template(ECHO_AUTH)?;
                r.set(39, rc::INVALID_TRANSACTION);
                Some(r)
            }
        }
    }

    fn network(&self, msg: &Message, session: &Session) -> Message {
        let mut r = msg
            .response_template(ECHO_NETWORK)
            .expect("0800 has a response MTI");
        let code = msg.get_str(70).unwrap_or("");
        let rc = match code {
            "001" => {
                session.signed_on.store(true, Ordering::Release);
                rc::APPROVED
            }
            "002" => {
                session.signed_on.store(false, Ordering::Release);
                rc::APPROVED
            }
            "301" => rc::APPROVED,
            _ => rc::INVALID_TRANSACTION,
        };
        r.set(39, rc);
        r
    }

    // ------------------------------------------------------------------
    // Authorization
    // ------------------------------------------------------------------

    async fn authorize(&self, msg: Message) -> Message {
        let t0 = Instant::now();
        let Some(key) = MatchKey::from_request(&msg) else {
            let mut r = msg.response_template(ECHO_AUTH).expect("request");
            r.set(39, rc::FORMAT_ERROR);
            self.stats.count_rc(rc::FORMAT_ERROR);
            return r;
        };
        let auth_ref = key.auth_ref();
        // Duplicate detection: an identical retransmission gets the original
        // answer; one that arrives while the original is still being
        // processed gets 94.
        let dup_key = format!("{}:{}", msg.mti.class(), auth_ref);
        match self.store.dup.entry(dup_key.clone()) {
            Entry::Occupied(e) => {
                let (state, _) = e.get();
                return match state {
                    DupState::Done(m) => {
                        tracing::info!(%auth_ref, "duplicate request: replaying original response");
                        (**m).clone()
                    }
                    DupState::InFlight => {
                        let mut r = msg.response_template(ECHO_AUTH).expect("request");
                        r.set(39, rc::DUPLICATE_TRANSMISSION);
                        r
                    }
                };
            }
            Entry::Vacant(v) => {
                v.insert((DupState::InFlight, Instant::now()));
            }
        }

        let d = if self.store.tombstones.contains_key(&auth_ref) {
            tracing::warn!(%auth_ref, "original arrived after its reversal: declining");
            Decision::decline(rc::DO_NOT_HONOR)
        } else {
            self.decide(&msg, &auth_ref).await
        };

        let mut r = msg.response_template(ECHO_AUTH).expect("request");
        r.set(39, d.rc);
        if let Some(code) = &d.auth_code {
            r.set(38, code.clone());
        }
        if d.stand_in {
            r.set(44, "STIP");
        }
        if let Some(t) = d.tag91 {
            r.set(55, tlv::encode(&[Tlv::new(0x91, t)]));
        }
        self.store.dup.insert(
            dup_key,
            (DupState::Done(Box::new(r.clone())), Instant::now()),
        );
        self.stats.count_rc(d.rc);
        self.stats.record("total_auth", t0.elapsed());
        r
    }

    async fn decide(&self, msg: &Message, auth_ref: &str) -> Decision {
        // ---- parse ----
        let track2 = msg.get_str(35).and_then(parse_track2);
        let pan = match msg.get_str(2).or(track2.as_ref().map(|t| t.pan.as_str())) {
            Some(p) => p.to_string(),
            None => return Decision::decline(rc::FORMAT_ERROR),
        };
        let cash = match msg.get_str(3).and_then(|p| p.get(0..2)) {
            Some("00") => false,
            Some("01") => true,
            Some(_) => return Decision::decline(rc::INVALID_TRANSACTION),
            None => return Decision::decline(rc::FORMAT_ERROR),
        };
        let amount: i64 = match msg.get_str(4).and_then(|a| a.parse().ok()) {
            Some(a) => a,
            None => return Decision::decline(rc::FORMAT_ERROR),
        };
        if amount <= 0 {
            return Decision::decline(rc::INVALID_AMOUNT);
        }
        let Some(currency) = msg.get_str(49) else {
            return Decision::decline(rc::FORMAT_ERROR);
        };
        let entry = msg.get_str(22).unwrap_or("000");
        let chip = entry.starts_with("05") || entry.starts_with("07");
        let magstripe =
            entry.starts_with("90") || entry.starts_with("02") || entry.starts_with("80");

        // ---- card ----
        if !cardcrypto::luhn::is_valid(&pan) {
            return Decision::decline(rc::INVALID_CARD);
        }
        let Some(card) = self.cards.get(&self.pan_ref(&pan)) else {
            return Decision::decline(rc::INVALID_CARD);
        };
        match card.status.as_str() {
            "ACTIVE" => {}
            "LOST" => return Decision::decline(rc::LOST_CARD),
            "STOLEN" => return Decision::decline(rc::STOLEN_CARD),
            "BLOCKED" => return Decision::decline(rc::RESTRICTED_CARD),
            _ => return Decision::decline(rc::DO_NOT_HONOR),
        }
        if currency != card.currency {
            return Decision::decline(rc::INVALID_TRANSACTION);
        }
        let presented_expiry = msg
            .get_str(14)
            .map(str::to_string)
            .or(track2.as_ref().map(|t| t.expiry.clone()));
        if let Some(e) = &presented_expiry {
            if *e != card.expiry {
                return Decision::decline(rc::EXPIRED_CARD);
            }
        }
        let now = Utc::now();
        let today_yymm = format!("{:02}{:02}", now.year() % 100, now.month());
        if card.expiry < today_yymm {
            return Decision::decline(rc::EXPIRED_CARD);
        }

        // ---- PIN ----
        let today = now.date_naive();
        let pin_failures = {
            let mut day = self.store.cards.entry(card.card_id).or_default();
            day.roll(today);
            day.pin_failures
        };
        if let Some(pb) = msg.get(52) {
            if pin_failures >= MAX_PIN_TRIES {
                return Decision::decline(rc::PIN_TRIES_EXCEEDED);
            }
            let t = Instant::now();
            let res = self
                .hsm
                .call(Command::VerifyPinPvv {
                    zpk: self.cfg.keys.zpk.clone(),
                    pvk: self.cfg.keys.pvk.clone(),
                    pin_block: hex::encode_upper(pb),
                    pan: pan.clone(),
                    pvki: card.pvki,
                    pvv: card.pvv.clone(),
                })
                .await;
            self.stats.record("hsm_pin", t.elapsed());
            let ok = match res {
                Ok(Reply::Verified { ok }) => ok,
                // A structurally invalid PIN block after decryption means a
                // wrong key/PAN or garbage: treat like a wrong PIN.
                Err(ClientError::Hsm(HsmError::PinBlockFormat(_))) => false,
                Ok(other) => {
                    tracing::error!(?other, "unexpected HSM reply");
                    return Decision::decline(rc::SYSTEM_MALFUNCTION);
                }
                Err(e) => {
                    tracing::error!(error = %e, "HSM PIN verification failed");
                    return Decision::decline(rc::SYSTEM_MALFUNCTION);
                }
            };
            let mut day = self.store.cards.entry(card.card_id).or_default();
            if ok {
                day.pin_failures = 0;
            } else {
                day.pin_failures += 1;
                return Decision::decline(if day.pin_failures > MAX_PIN_TRIES {
                    rc::PIN_TRIES_EXCEEDED
                } else {
                    rc::INCORRECT_PIN
                });
            }
        } else if cash {
            // Cash always requires online PIN in this profile.
            return Decision::decline(rc::INCORRECT_PIN);
        }

        // ---- card authentication: ARQC (chip) or CVV (magstripe) ----
        let mut chip_ctx = None;
        if chip {
            match self.verify_chip(msg, &card, &pan, amount).await {
                Ok(ctx) => chip_ctx = Some(ctx),
                Err(rc) => return Decision::decline(rc),
            }
        } else if magstripe {
            let Some(t2) = &track2 else {
                return Decision::decline(rc::FORMAT_ERROR);
            };
            let Some(cvv) = t2.discretionary.get(5..8) else {
                return Decision::decline(rc::FORMAT_ERROR);
            };
            let t = Instant::now();
            let res = self
                .hsm
                .call(Command::VerifyCvv {
                    cvk: self.cfg.keys.cvk.clone(),
                    pan: pan.clone(),
                    expiry: t2.expiry.clone(),
                    service_code: t2.service_code.clone(),
                    cvv: cvv.to_string(),
                })
                .await;
            self.stats.record("hsm_cvv", t.elapsed());
            match res {
                Ok(Reply::Verified { ok: true }) => {}
                Ok(_) => return Decision::decline(rc::CRYPTOGRAPHIC_FAILURE),
                Err(e) => {
                    tracing::error!(error = %e, "HSM CVV verification failed");
                    return Decision::decline(rc::SYSTEM_MALFUNCTION);
                }
            }
        }

        // ---- switch-side limits (reserve atomically, release on decline) ----
        if amount > card.per_txn_limit_minor {
            return self
                .finish_chip(Decision::decline(rc::EXCEEDS_AMOUNT_LIMIT), chip_ctx)
                .await;
        }
        {
            let mut day = self.store.cards.entry(card.card_id).or_default();
            day.roll(today);
            if day.approvals >= card.daily_txn_count_limit {
                drop(day);
                return self
                    .finish_chip(Decision::decline(rc::EXCEEDS_FREQUENCY_LIMIT), chip_ctx)
                    .await;
            }
            if cash && day.cash_minor + amount > card.daily_cash_limit_minor {
                drop(day);
                return self
                    .finish_chip(Decision::decline(rc::EXCEEDS_AMOUNT_LIMIT), chip_ctx)
                    .await;
            }
            day.approvals += 1;
            if cash {
                day.cash_minor += amount;
            }
        }

        // ---- issuer, or stand-in ----
        let req = AuthRequest {
            auth_ref: auth_ref.to_string(),
            card_id: card.card_id,
            account_id: card.account_id,
            amount_minor: amount,
            currency: currency.to_string(),
            txn_type: if cash { "CASH" } else { "PURCHASE" }.into(),
            mcc: msg.get_str(18).unwrap_or("0000").into(),
            stan: msg.get_str(11).unwrap_or_default().into(),
            rrn: msg.get_str(37).unwrap_or_default().trim().into(),
            terminal_id: msg.get_str(41).unwrap_or_default().trim().into(),
            merchant_id: msg.get_str(42).unwrap_or_default().trim().into(),
            merchant_name: msg.get_str(43).unwrap_or_default().trim().into(),
            entry_mode: entry.into(),
            transmitted_at: msg.get_str(7).unwrap_or_default().into(),
        };
        let mut decision = if self.circuit.allow() {
            let t = Instant::now();
            let res = self.issuer.authorize(req.clone()).await;
            self.stats.record("issuer_authorize", t.elapsed());
            match res {
                Ok(r) => {
                    self.circuit.success();
                    Decision {
                        rc: static_rc(&r.response_code),
                        auth_code: r.auth_code.filter(|_| r.approved),
                        stand_in: false,
                        tag91: None,
                    }
                }
                Err(e) if e.is_outage() => {
                    tracing::warn!(error = %e, %auth_ref, "issuer did not answer in time: standing in");
                    self.circuit.failure();
                    self.stand_in(req, &card, today).await
                }
                Err(e) => {
                    tracing::error!(error = %e, %auth_ref, "issuer rejected request");
                    Decision::decline(rc::DO_NOT_HONOR)
                }
            }
        } else {
            self.stand_in(req, &card, today).await
        };

        if decision.rc != rc::APPROVED {
            let mut day = self.store.cards.entry(card.card_id).or_default();
            day.approvals = day.approvals.saturating_sub(1);
            if cash {
                day.cash_minor -= amount;
            }
            decision.auth_code = None;
        }
        self.store.auths.insert(
            auth_ref.to_string(),
            AuthRecord {
                card_id: card.card_id,
                amount_minor: amount,
                approved: decision.rc == rc::APPROVED,
                stand_in: decision.stand_in,
                response_code: decision.rc.to_string(),
                cash,
                at: Instant::now(),
            },
        );
        self.finish_chip(decision, chip_ctx).await
    }

    /// Stand-in processing: approve within stand-in limits, and persist an
    /// 0120 advice for the issuer *before* answering the terminal.
    async fn stand_in(
        &self,
        req: AuthRequest,
        card: &CardProfile,
        today: chrono::NaiveDate,
    ) -> Decision {
        let amount = req.amount_minor;
        let approve = {
            let mut day = self.store.cards.entry(card.card_id).or_default();
            day.roll(today);
            if amount <= self.cfg.stand_in.per_txn_limit_minor
                && day.stand_in_minor + amount <= self.cfg.stand_in.daily_limit_minor
            {
                day.stand_in_minor += amount;
                true
            } else {
                false
            }
        };
        let (rc_, auth_code) = if approve {
            (
                rc::APPROVED,
                Some(format!("S{:05}", rand::thread_rng().gen_range(0..100_000))),
            )
        } else {
            (rc::ISSUER_UNAVAILABLE, None)
        };
        let advice = AdviceRequest {
            advice_id: format!("STIP-{}", req.auth_ref),
            source: "SWITCH_STIP".into(),
            response_code: rc_.into(),
            auth_code: auth_code.clone(),
            auth: req,
        };
        let t = Instant::now();
        let res = self
            .journal
            .enqueue("0120", SafItem::AuthAdvice(advice))
            .await;
        self.stats.record("stip_journal_fsync", t.elapsed());
        if let Err(e) = res {
            tracing::error!(error = %e, "cannot persist stand-in advice: declining");
            if approve {
                let mut day = self.store.cards.entry(card.card_id).or_default();
                day.stand_in_minor -= amount;
            }
            return Decision::decline(rc::SYSTEM_MALFUNCTION);
        }
        Decision {
            rc: rc_,
            auth_code,
            stand_in: true,
            tag91: None,
        }
    }

    async fn verify_chip(
        &self,
        msg: &Message,
        card: &CardProfile,
        pan: &str,
        amount: i64,
    ) -> Result<ChipCtx, &'static str> {
        let list = msg
            .get(55)
            .and_then(|b| tlv::parse(b).ok())
            .ok_or(rc::FORMAT_ERROR)?;
        let arqc: [u8; 8] = fixed(&list, 0x9F26).ok_or(rc::FORMAT_ERROR)?;
        let cid = tlv::find(&list, 0x9F27)
            .and_then(|c| c.first().copied())
            .unwrap_or(0x80);
        if cid & 0xC0 != 0x80 {
            // The card did not ask to go online (TC/AAC in an online request).
            return Err(rc::DO_NOT_HONOR);
        }
        let iad = tlv::find(&list, 0x9F10).ok_or(rc::FORMAT_ERROR)?.to_vec();
        let d = ArqcData {
            amount_authorised: fixed(&list, 0x9F02).ok_or(rc::FORMAT_ERROR)?,
            amount_other: fixed(&list, 0x9F03).unwrap_or([0; 6]),
            terminal_country: fixed(&list, 0x9F1A).ok_or(rc::FORMAT_ERROR)?,
            tvr: fixed(&list, 0x95).ok_or(rc::FORMAT_ERROR)?,
            currency: fixed(&list, 0x5F2A).ok_or(rc::FORMAT_ERROR)?,
            txn_date: fixed(&list, 0x9A).ok_or(rc::FORMAT_ERROR)?,
            txn_type: fixed::<1>(&list, 0x9C).ok_or(rc::FORMAT_ERROR)?[0],
            unpredictable: fixed(&list, 0x9F37).ok_or(rc::FORMAT_ERROR)?,
            aip: fixed(&list, 0x82).ok_or(rc::FORMAT_ERROR)?,
            atc: fixed(&list, 0x9F36).ok_or(rc::FORMAT_ERROR)?,
            iad,
        };
        // The cryptogram must cover the amount actually being authorised.
        if d.amount_authorised != bcd_amount(amount) {
            tracing::warn!("ARQC amount (9F02) differs from field 4");
            return Err(rc::CRYPTOGRAPHIC_FAILURE);
        }
        let cvn = Cvn::from_iad(&d.iad).ok_or(rc::CRYPTOGRAPHIC_FAILURE)?;
        if cvn.code() != card.cvn {
            tracing::warn!(card_cvn = card.cvn, iad_cvn = cvn.code(), "CVN mismatch");
            return Err(rc::CRYPTOGRAPHIC_FAILURE);
        }
        let atc_val = u16::from_be_bytes(d.atc);
        let psn = tlv::find(&list, 0x5F34)
            .and_then(|v| v.first())
            .map(|b| format!("{:02X}", b))
            .or_else(|| msg.get_str(23).map(|s| s[1..].to_string()))
            .unwrap_or_else(|| card.psn.clone());
        let data = cvn.ac_data(&d).map_err(|_| rc::FORMAT_ERROR)?;

        let t = Instant::now();
        let res = self
            .hsm
            .call(Command::VerifyArqc {
                imk_ac: self.cfg.keys.imk_ac.clone(),
                cvn: cvn.code(),
                pan: pan.to_string(),
                psn: psn.clone(),
                atc: hex::encode_upper(d.atc),
                data: hex::encode_upper(&data),
                arqc: hex::encode_upper(arqc),
                // Optimistically request the approval ARPC in the same call;
                // a decline costs one more HSM call (see finish_chip).
                arpc: Some(arpc_method(cvn, rc::APPROVED)),
            })
            .await;
        self.stats.record("hsm_arqc", t.elapsed());
        let tag91 = match res {
            Ok(Reply::Arqc { ok: true, tag91 }) => tag91,
            Ok(Reply::Arqc { ok: false, .. }) => {
                tracing::warn!(atc = atc_val, "ARQC verification failed");
                return Err(rc::CRYPTOGRAPHIC_FAILURE);
            }
            Ok(other) => {
                tracing::error!(?other, "unexpected HSM reply");
                return Err(rc::SYSTEM_MALFUNCTION);
            }
            Err(e) => {
                tracing::error!(error = %e, "HSM ARQC verification failed");
                return Err(rc::SYSTEM_MALFUNCTION);
            }
        };
        // Replay protection: the ATC must strictly increase per card. Only
        // checked after the cryptogram is proven genuine, so a forged
        // message cannot advance the counter.
        {
            let mut day = self.store.cards.entry(card.card_id).or_default();
            if let Some(last) = day.last_atc {
                if atc_val <= last {
                    tracing::warn!(atc = atc_val, last, "ATC replay detected");
                    return Err(rc::CRYPTOGRAPHIC_FAILURE);
                }
            }
            day.last_atc = Some(atc_val);
        }
        Ok(ChipCtx {
            cvn,
            pan: pan.to_string(),
            psn,
            atc: d.atc,
            data,
            arqc,
            approval_tag91: tag91.and_then(|h| hex::decode(h).ok()),
        })
    }

    /// Attach the ARPC (issuer authentication data, tag 91) for chip
    /// transactions. Approval ARPCs were computed during verification; a
    /// decline needs one more HSM call with the decline ARC/CSU.
    async fn finish_chip(&self, mut d: Decision, ctx: Option<ChipCtx>) -> Decision {
        let Some(ctx) = ctx else { return d };
        if d.rc == rc::APPROVED {
            d.tag91 = ctx.approval_tag91;
            return d;
        }
        let res = self
            .hsm
            .call(Command::VerifyArqc {
                imk_ac: self.cfg.keys.imk_ac.clone(),
                cvn: ctx.cvn.code(),
                pan: ctx.pan,
                psn: ctx.psn,
                atc: hex::encode_upper(ctx.atc),
                data: hex::encode_upper(&ctx.data),
                arqc: hex::encode_upper(ctx.arqc),
                arpc: Some(arpc_method(ctx.cvn, d.rc)),
            })
            .await;
        if let Ok(Reply::Arqc { tag91: Some(h), .. }) = res {
            d.tag91 = hex::decode(h).ok();
        }
        d
    }

    // ------------------------------------------------------------------
    // Advices from the acquirer (0120 / 0220)
    // ------------------------------------------------------------------

    async fn acquirer_advice(&self, msg: Message) -> Message {
        let mut r = msg.response_template(ECHO_AUTH).expect("advice");
        let rc_ = self.acquirer_advice_inner(&msg).await;
        r.set(39, rc_);
        self.stats.count_rc(rc_);
        r
    }

    async fn acquirer_advice_inner(&self, msg: &Message) -> &'static str {
        let Some(key) = MatchKey::from_request(msg) else {
            return rc::FORMAT_ERROR;
        };
        let pan = msg
            .get_str(2)
            .map(str::to_string)
            .or_else(|| msg.get_str(35).and_then(parse_track2).map(|t| t.pan));
        let Some(card) = pan.and_then(|p| self.cards.get(&self.pan_ref(&p))) else {
            return rc::INVALID_CARD;
        };
        let Some(amount) = msg.get_str(4).and_then(|a| a.parse::<i64>().ok()) else {
            return rc::FORMAT_ERROR;
        };
        let cash = msg.get_str(3).is_some_and(|p| p.starts_with("01"));
        let advice = AdviceRequest {
            advice_id: format!("ACQ-{}", key.auth_ref()),
            source: "ACQUIRER".into(),
            response_code: msg.get_str(39).unwrap_or("00").into(),
            auth_code: msg.get_str(38).map(str::to_string),
            auth: AuthRequest {
                auth_ref: key.auth_ref(),
                card_id: card.card_id,
                account_id: card.account_id,
                amount_minor: amount,
                currency: msg.get_str(49).unwrap_or(&card.currency).into(),
                txn_type: if cash { "CASH" } else { "PURCHASE" }.into(),
                mcc: msg.get_str(18).unwrap_or("0000").into(),
                stan: key.stan.clone(),
                rrn: key.rrn.clone(),
                terminal_id: key.terminal.clone(),
                merchant_id: msg.get_str(42).unwrap_or_default().trim().into(),
                merchant_name: msg.get_str(43).unwrap_or_default().trim().into(),
                entry_mode: msg.get_str(22).unwrap_or("000").into(),
                transmitted_at: msg.get_str(7).unwrap_or_default().into(),
            },
        };
        self.deliver(SafItem::AuthAdvice(advice), "0120").await
    }

    /// Send an advice/reversal to the issuer now if possible, otherwise
    /// store it for forwarding. Ordering: while anything is queued, new
    /// items are queued behind it so the issuer sees them in order.
    async fn deliver(&self, item: SafItem, mti: &str) -> &'static str {
        if self.journal.pending_len() == 0 && self.circuit.allow() {
            let res = match &item {
                SafItem::AuthAdvice(a) => self.issuer.advice(a.clone()).await.map(|_| ()),
                SafItem::Reversal(r) => self.issuer.reverse(r.clone()).await.map(|_| ()),
            };
            match res {
                Ok(()) => {
                    self.circuit.success();
                    return rc::APPROVED;
                }
                Err(e) if e.is_outage() => self.circuit.failure(),
                Err(e) => {
                    tracing::error!(error = %e, "issuer rejected advice");
                    return rc::DO_NOT_HONOR;
                }
            }
        }
        match self.journal.enqueue(mti, item).await {
            Ok(_) => rc::APPROVED,
            Err(e) => {
                tracing::error!(error = %e, "cannot persist advice");
                rc::SYSTEM_MALFUNCTION
            }
        }
    }

    // ------------------------------------------------------------------
    // Reversals (0400 / 0420, repeats 0401 / 0421)
    // ------------------------------------------------------------------

    async fn reversal(&self, msg: Message) -> Message {
        let t0 = Instant::now();
        let mut r = msg.response_template(ECHO_REVERSAL).expect("reversal");
        let rc_ = self.reversal_inner(&msg).await;
        r.set(39, rc_);
        self.stats.count_rc(rc_);
        self.stats.record("reversal", t0.elapsed());
        r
    }

    async fn reversal_inner(&self, msg: &Message) -> &'static str {
        let Some(key) = MatchKey::from_reversal(msg) else {
            return rc::FORMAT_ERROR;
        };
        let auth_ref = key.auth_ref();
        // Field 95: first 12 digits = actual (remaining) transaction amount.
        let replacement = msg
            .get_str(95)
            .and_then(|f| f.get(0..12))
            .and_then(|a| a.parse::<i64>().ok())
            .filter(|a| *a > 0);
        let reversal_ref = format!(
            "{auth_ref}:{}",
            replacement.map_or("FULL".to_string(), |a| a.to_string())
        );
        // Idempotency: a repeat (0401/0421) or retransmission of a reversal
        // already processed returns the same answer and does nothing.
        if let Some(prev) = self.store.reversals.get(&reversal_ref) {
            tracing::info!(%reversal_ref, "duplicate reversal: replaying result");
            return static_rc(&prev.0);
        }

        let original = self.store.auths.get(&auth_ref).map(|r| r.clone());
        if let Some(o) = &original {
            if !o.approved {
                self.store
                    .reversals
                    .insert(reversal_ref, (rc::APPROVED.into(), Instant::now()));
                return rc::APPROVED;
            }
        }
        let req = ReversalRequest {
            reversal_ref: reversal_ref.clone(),
            auth_ref: auth_ref.clone(),
            replacement_amount_minor: replacement,
            reason: if msg.mti.function() == 2 {
                "ADVICE"
            } else {
                "REQUEST"
            }
            .into(),
        };

        let mut result = rc::APPROVED;
        let mut queued = false;
        if self.journal.pending_len() == 0 && self.circuit.allow() {
            match self.issuer.reverse(req.clone()).await {
                Ok(resp) => {
                    self.circuit.success();
                    if resp.status == "NOT_FOUND" {
                        self.store
                            .tombstones
                            .insert(auth_ref.clone(), Instant::now());
                        // A reversal *request* for an unknown original gets 25;
                        // a reversal *advice* is always acknowledged.
                        if msg.mti.function() == 0 {
                            result = rc::UNABLE_TO_LOCATE_ORIGINAL;
                        }
                    }
                }
                Err(e) if e.is_outage() => {
                    self.circuit.failure();
                    queued = true;
                }
                Err(e) => {
                    tracing::error!(error = %e, "issuer rejected reversal");
                    result = rc::SYSTEM_MALFUNCTION;
                }
            }
        } else {
            queued = true;
        }
        if queued {
            if original.is_none() {
                self.store
                    .tombstones
                    .insert(auth_ref.clone(), Instant::now());
            }
            if let Err(e) = self.journal.enqueue("0420", SafItem::Reversal(req)).await {
                tracing::error!(error = %e, "cannot persist reversal");
                return rc::SYSTEM_MALFUNCTION;
            }
        }
        // Release switch-side counters held by the original.
        if result == rc::APPROVED {
            if let Some(o) = &original {
                let mut day = self.store.cards.entry(o.card_id).or_default();
                let released = o.amount_minor - replacement.unwrap_or(0);
                if replacement.is_none() {
                    day.approvals = day.approvals.saturating_sub(1);
                }
                if o.cash {
                    day.cash_minor = (day.cash_minor - released).max(0);
                }
                if o.stand_in {
                    day.stand_in_minor = (day.stand_in_minor - released).max(0);
                }
            }
        }
        self.store
            .reversals
            .insert(reversal_ref, (result.to_string(), Instant::now()));
        result
    }

    // ------------------------------------------------------------------
    // Background work
    // ------------------------------------------------------------------

    /// Forward queued advices in order. Stops at the first outage.
    pub async fn replay_saf(&self) -> usize {
        let mut sent = 0;
        for e in self.journal.pending() {
            let res = match e.item.clone() {
                SafItem::AuthAdvice(a) => self.issuer.advice(a).await.map(|_| ()),
                SafItem::Reversal(r) => self.issuer.reverse(r).await.map(|_| ()),
            };
            match res {
                Ok(()) => {
                    self.circuit.success();
                    self.journal.ack(e.seq).await;
                    sent += 1;
                }
                Err(err) if err.is_outage() => {
                    self.circuit.failure();
                    break;
                }
                Err(err) => {
                    // Poison message: log it (dead letter) and move on so one
                    // bad advice cannot block the queue forever.
                    tracing::error!(seq = e.seq, error = %err, entry = ?e, "dead-lettering SAF entry");
                    self.journal.ack(e.seq).await;
                }
            }
        }
        if sent > 0 {
            tracing::info!(sent, remaining = self.journal.pending_len(), "SAF replay");
        }
        sent
    }

    pub async fn refresh_cards(&self) -> anyhow::Result<usize> {
        let cards = self
            .issuer
            .card_snapshot()
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        let n = cards.len();
        self.cards.replace_all(cards);
        if let Err(e) = self.cards.save(&self.cfg.card_snapshot_file) {
            tracing::warn!(error = %e, "could not persist card snapshot");
        }
        Ok(n)
    }

    /// Spawn the background loops: card refresh, issuer health probe,
    /// SAF replay and state sweeping.
    pub fn spawn_background(self: &Arc<Self>) {
        let s = self.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(s.cfg.card_refresh_secs.max(1)));
            loop {
                iv.tick().await;
                if !s.circuit.is_open() {
                    if let Err(e) = s.refresh_cards().await {
                        tracing::debug!(error = %e, "card refresh failed; keeping cached snapshot");
                    }
                }
            }
        });
        let s = self.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_millis(250));
            loop {
                iv.tick().await;
                if s.circuit.is_open() {
                    if s.issuer.health().await.is_ok() {
                        s.circuit.success();
                    } else {
                        continue;
                    }
                }
                if s.journal.pending_len() > 0 {
                    s.replay_saf().await;
                }
            }
        });
        let s = self.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(60));
            loop {
                iv.tick().await;
                s.store.sweep(Duration::from_secs(24 * 3600));
                s.store
                    .dup
                    .retain(|_, (_, t)| t.elapsed() < Duration::from_secs(600));
            }
        });
    }
}

/// ARPC parameters for a final response code. CVN 10 uses method 1 with
/// the 2-character response code as ARC; CVN 18 uses method 2 with a CSU
/// whose "issuer approves" bit (byte 2, bit 8) reflects the decision
/// (simplified Visa CSU).
fn arpc_method(cvn: Cvn, rc: &str) -> ArpcMethod {
    match cvn {
        Cvn::Visa10 => ArpcMethod::Method1 {
            arc: hex::encode_upper(rc.as_bytes()),
        },
        Cvn::Visa18 => ArpcMethod::Method2 {
            csu: if rc == rc::APPROVED {
                "00800000"
            } else {
                "00000000"
            }
            .into(),
            prop: String::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn track2_parsing() {
        let t = parse_track2("4761739001010010=28122011234567890").unwrap();
        assert_eq!(t.pan, "4761739001010010");
        assert_eq!(t.expiry, "2812");
        assert_eq!(t.service_code, "201");
        assert_eq!(&t.discretionary[5..8], "678");
        assert!(parse_track2("4761=28").is_none());
    }

    #[test]
    fn bcd_amounts() {
        assert_eq!(bcd_amount(1500), [0, 0, 0, 0, 0x15, 0x00]);
        assert_eq!(
            bcd_amount(123456789012),
            [0x12, 0x34, 0x56, 0x78, 0x90, 0x12]
        );
    }

    #[test]
    fn reversal_key_matches_original() {
        let orig = Message::new(iso8583::Mti::AUTH_REQUEST)
            .with(7, "1002143015")
            .with(11, "000123")
            .with(37, "627514000123")
            .with(41, "TERM0001");
        let rev = Message::new(iso8583::Mti::REVERSAL_REQUEST)
            .with(7, "1002143115")
            .with(11, "000124")
            .with(37, "627514000123")
            .with(41, "TERM0001")
            .with(90, "010000012310021430150000000000100000000000");
        assert_eq!(
            MatchKey::from_request(&orig).unwrap().auth_ref(),
            MatchKey::from_reversal(&rev).unwrap().auth_ref()
        );
    }
}
