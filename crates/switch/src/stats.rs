//! Latency histograms per processing stage and response-code counters.

use dashmap::DashMap;
use hdrhistogram::Histogram;
use serde::Serialize;
use std::sync::Mutex;
use std::time::Duration;

pub const STAGES: &[&str] = &[
    "total_auth",
    "hsm_pin",
    "hsm_arqc",
    "hsm_cvv",
    "issuer_authorize",
    "stip_journal_fsync",
    "reversal",
];

pub struct Stats {
    hists: Vec<Mutex<Histogram<u64>>>,
    rc: DashMap<String, u64>,
}

#[derive(Serialize)]
pub struct StageSummary {
    pub stage: String,
    pub count: u64,
    pub p50_us: u64,
    pub p90_us: u64,
    pub p99_us: u64,
    pub max_us: u64,
    pub mean_us: f64,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            hists: STAGES
                .iter()
                .map(|_| {
                    Mutex::new(Histogram::new_with_bounds(1, 60_000_000, 3).expect("histogram"))
                })
                .collect(),
            rc: DashMap::new(),
        }
    }
}

impl Stats {
    pub fn record(&self, stage: &str, d: Duration) {
        if let Some(i) = STAGES.iter().position(|s| *s == stage) {
            let us = (d.as_micros() as u64).clamp(1, 60_000_000);
            let _ = self.hists[i].lock().expect("hist lock").record(us);
        }
    }

    pub fn count_rc(&self, rc: &str) {
        *self.rc.entry(rc.to_string()).or_insert(0) += 1;
    }

    pub fn summary(&self) -> serde_json::Value {
        let stages: Vec<StageSummary> = STAGES
            .iter()
            .zip(&self.hists)
            .map(|(name, h)| {
                let h = h.lock().expect("hist lock");
                StageSummary {
                    stage: name.to_string(),
                    count: h.len(),
                    p50_us: h.value_at_quantile(0.5),
                    p90_us: h.value_at_quantile(0.9),
                    p99_us: h.value_at_quantile(0.99),
                    max_us: h.max(),
                    mean_us: (h.mean() * 10.0).round() / 10.0,
                }
            })
            .filter(|s| s.count > 0)
            .collect();
        let mut rc: Vec<(String, u64)> = self
            .rc
            .iter()
            .map(|e| (e.key().clone(), *e.value()))
            .collect();
        rc.sort();
        serde_json::json!({ "stages": stages, "response_codes": rc })
    }
}
