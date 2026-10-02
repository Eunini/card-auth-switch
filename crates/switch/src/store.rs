//! In-memory transactional state: duplicate detection, the authorization
//! log used to match reversals, idempotent reversal results, and per-card
//! daily counters (velocity, cash, stand-in exposure, PIN tries, ATC).
//!
//! This state is an optimisation and a guard, not the system of record:
//! the issuer back office de-duplicates by `auth_ref` / `reversal_ref`, so
//! a switch restart cannot double-post. Entries are swept after a TTL.

use chrono::NaiveDate;
use dashmap::DashMap;
use iso8583::Message;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub enum DupState {
    InFlight,
    Done(Box<Message>),
}

#[derive(Debug, Clone)]
pub struct AuthRecord {
    pub card_id: i64,
    pub amount_minor: i64,
    pub approved: bool,
    pub stand_in: bool,
    pub response_code: String,
    pub cash: bool,
    pub at: Instant,
}

#[derive(Debug, Clone, Default)]
pub struct CardDay {
    pub day: Option<NaiveDate>,
    pub approvals: u32,
    pub cash_minor: i64,
    pub stand_in_minor: i64,
    pub pin_failures: u32,
    pub last_atc: Option<u16>,
}

impl CardDay {
    pub fn roll(&mut self, today: NaiveDate) {
        if self.day != Some(today) {
            self.day = Some(today);
            self.approvals = 0;
            self.cash_minor = 0;
            self.stand_in_minor = 0;
        }
    }
}

#[derive(Default)]
pub struct Store {
    pub dup: DashMap<String, (DupState, Instant)>,
    pub auths: DashMap<String, AuthRecord>,
    pub reversals: DashMap<String, (String, Instant)>,
    /// Reversals that arrived before (or without) their original: a late
    /// original with the same key must not be approved.
    pub tombstones: DashMap<String, Instant>,
    pub cards: DashMap<i64, CardDay>,
}

impl Store {
    pub fn sweep(&self, ttl: Duration) {
        let now = Instant::now();
        self.dup.retain(|_, (_, t)| now.duration_since(*t) < ttl);
        self.auths.retain(|_, r| now.duration_since(r.at) < ttl);
        self.reversals
            .retain(|_, (_, t)| now.duration_since(*t) < ttl);
        self.tombstones.retain(|_, t| now.duration_since(*t) < ttl);
    }
}
