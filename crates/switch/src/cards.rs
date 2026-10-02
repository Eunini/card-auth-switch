//! Card profile cache.
//!
//! The issuer back office is the system of record for cards. The switch
//! keeps a periodically refreshed snapshot so that card checks (status,
//! expiry, PIN/CVV/ARQC parameters, limits) work during an issuer outage,
//! and persists the last snapshot to disk for a cold start in stand-in.
//! Cards are keyed by an HMAC of the PAN; the issuer never stores PANs.

use dashmap::DashMap;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CardProfile {
    pub card_id: i64,
    pub account_id: i64,
    pub pan_ref: String,
    pub last4: String,
    /// YYMM
    pub expiry: String,
    /// ACTIVE, BLOCKED, LOST, STOLEN, CLOSED
    pub status: String,
    pub pvv: String,
    pub pvki: u8,
    pub service_code: String,
    pub psn: String,
    /// EMV cryptogram version number (10 or 18).
    pub cvn: u8,
    pub currency: String,
    pub per_txn_limit_minor: i64,
    pub daily_cash_limit_minor: i64,
    pub daily_txn_count_limit: u32,
}

pub fn pan_ref(key: &[u8], pan: &str) -> String {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(pan.as_bytes());
    hex::encode(&m.finalize().into_bytes()[..16])
}

#[derive(Default)]
pub struct CardCache {
    by_ref: DashMap<String, Arc<CardProfile>>,
}

impl CardCache {
    pub fn get(&self, pan_ref: &str) -> Option<Arc<CardProfile>> {
        self.by_ref.get(pan_ref).map(|e| e.value().clone())
    }

    pub fn replace_all(&self, cards: Vec<CardProfile>) {
        let keep: std::collections::HashSet<String> =
            cards.iter().map(|c| c.pan_ref.clone()).collect();
        for c in cards {
            self.by_ref.insert(c.pan_ref.clone(), Arc::new(c));
        }
        self.by_ref.retain(|k, _| keep.contains(k));
    }

    pub fn len(&self) -> usize {
        self.by_ref.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_ref.is_empty()
    }

    pub fn snapshot(&self) -> Vec<CardProfile> {
        self.by_ref.iter().map(|e| (**e.value()).clone()).collect()
    }

    pub fn save(&self, path: &str) -> std::io::Result<()> {
        let tmp = format!("{path}.tmp");
        if let Some(dir) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&tmp, serde_json::to_vec(&self.snapshot())?)?;
        std::fs::rename(tmp, path)
    }

    pub fn load(&self, path: &str) -> std::io::Result<usize> {
        let cards: Vec<CardProfile> = serde_json::from_slice(&std::fs::read(path)?)?;
        let n = cards.len();
        self.replace_all(cards);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pan_ref_is_keyed_and_stable() {
        let a = pan_ref(b"k1", "4761739001010010");
        assert_eq!(a, pan_ref(b"k1", "4761739001010010"));
        assert_ne!(a, pan_ref(b"k2", "4761739001010010"));
        assert_eq!(a.len(), 32);
    }
}
