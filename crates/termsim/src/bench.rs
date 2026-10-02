//! Load generator: closed-loop workers over pipelined TCP connections.
//!
//! Each worker owns a disjoint slice of cards (so per-card ATCs stay
//! monotonic, as on real cards) and its own terminal id (so STANs are
//! unique), and sends chip + PIN authorizations back to back. Latency is
//! measured from just before the request is written to when its response
//! is read, i.e. end to end over TCP through switch, HSM and issuer.

use crate::cards::CardSecret;
use crate::client::AcquirerClient;
use crate::emvcard::EmvCard;
use crate::keys::TestKeys;
use crate::terminal::{Entry, Terminal, TxnOpts};
use hdrhistogram::Histogram;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct BenchOpts {
    pub switch_addr: String,
    pub connections: usize,
    pub workers: usize,
    pub warmup: Duration,
    pub duration: Duration,
    pub mode: String,
    pub amount_minor: i64,
}

#[derive(Serialize)]
pub struct BenchResult {
    pub mode: String,
    pub connections: usize,
    pub workers: usize,
    pub duration_s: f64,
    pub requests: u64,
    pub throughput_per_s: f64,
    pub p50_ms: f64,
    pub p90_ms: f64,
    pub p99_ms: f64,
    pub p999_ms: f64,
    pub max_ms: f64,
    pub response_codes: BTreeMap<String, u64>,
    pub errors: u64,
}

struct Shared {
    hist: Histogram<u64>,
    rcs: BTreeMap<String, u64>,
    errors: u64,
}

pub async fn run(
    keys: TestKeys,
    cards: Vec<CardSecret>,
    o: BenchOpts,
) -> anyhow::Result<BenchResult> {
    anyhow::ensure!(
        cards.len() >= o.workers,
        "need at least one card per worker"
    );
    let mut clients = Vec::new();
    for _ in 0..o.connections.max(1) {
        clients.push(Arc::new(AcquirerClient::connect(&o.switch_addr).await?));
    }
    // Sign on every connection.
    for (i, c) in clients.iter().enumerate() {
        let mut t = Terminal::new(&format!("BSIGN{i:03}"), &keys);
        let (r, _) = c.send(&t.sign_on()).await?;
        anyhow::ensure!(r.get_str(39) == Some("00"), "sign-on failed");
    }
    let shared = Arc::new(Mutex::new(Shared {
        hist: Histogram::new_with_bounds(1, 60_000_000, 3)?,
        rcs: BTreeMap::new(),
        errors: 0,
    }));
    let recording = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let per = cards.len() / o.workers;
    let mut handles = Vec::new();
    for w in 0..o.workers {
        let slice: Vec<CardSecret> = cards[w * per..(w + 1) * per].to_vec();
        let client = clients[w % clients.len()].clone();
        let keys = keys.clone();
        let (shared, recording, stop) = (shared.clone(), recording.clone(), stop.clone());
        let mode = o.mode.clone();
        let amount = o.amount_minor;
        handles.push(tokio::spawn(async move {
            let mut emv: Vec<EmvCard> = slice
                .into_iter()
                .map(|s| EmvCard::personalise(s, &keys).expect("personalise"))
                .collect();
            let mut term = Terminal::new(&format!("B{w:05}"), &keys).with_stan(1);
            let mut local = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).expect("hist");
            let mut rcs: BTreeMap<String, u64> = BTreeMap::new();
            let mut errors = 0u64;
            let mut i = 0usize;
            while !stop.load(Ordering::Relaxed) {
                let card = &mut emv[i % per];
                i += 1;
                let mut opts = TxnOpts::chip_pin(&card.secret.pin);
                match mode.as_str() {
                    "chip" => opts.pin = None,
                    "magstripe" => {
                        opts.entry = Entry::Magstripe;
                        opts.pin = None;
                    }
                    _ => {}
                }
                let b = match term.auth(card, amount, &opts) {
                    Ok(b) => b,
                    Err(_) => {
                        errors += 1;
                        continue;
                    }
                };
                let t0 = Instant::now();
                let res = client.send(&b.msg).await;
                let us = t0.elapsed().as_micros() as u64;
                if recording.load(Ordering::Relaxed) {
                    match res {
                        Ok((r, _)) => {
                            let _ = local.record(us.max(1));
                            *rcs.entry(r.get_str(39).unwrap_or("??").to_string())
                                .or_insert(0) += 1;
                        }
                        Err(_) => errors += 1,
                    }
                }
            }
            let mut s = shared.lock().expect("lock");
            let _ = s.hist.add(&local);
            for (k, v) in rcs {
                *s.rcs.entry(k).or_insert(0) += v;
            }
            s.errors += errors;
        }));
    }
    tokio::time::sleep(o.warmup).await;
    recording.store(true, Ordering::SeqCst);
    let t0 = Instant::now();
    tokio::time::sleep(o.duration).await;
    recording.store(false, Ordering::SeqCst);
    let elapsed = t0.elapsed().as_secs_f64();
    stop.store(true, Ordering::SeqCst);
    for h in handles {
        let _ = h.await;
    }
    let s = shared.lock().expect("lock");
    let ms = |q: f64| s.hist.value_at_quantile(q) as f64 / 1000.0;
    Ok(BenchResult {
        mode: o.mode,
        connections: o.connections,
        workers: o.workers,
        duration_s: (elapsed * 10.0).round() / 10.0,
        requests: s.hist.len(),
        throughput_per_s: (s.hist.len() as f64 / elapsed).round(),
        p50_ms: ms(0.5),
        p90_ms: ms(0.9),
        p99_ms: ms(0.99),
        p999_ms: ms(0.999),
        max_ms: s.hist.max() as f64 / 1000.0,
        response_codes: s.rcs.clone(),
        errors: s.errors,
    })
}

/// Direct load on the issuer's internal authorize endpoint, to isolate its
/// share of the end-to-end latency.
pub async fn run_issuer(
    issuer_url: &str,
    targets: Vec<(i64, i64)>,
    workers: usize,
    warmup: Duration,
    duration: Duration,
) -> anyhow::Result<BenchResult> {
    let http = reqwest::Client::builder()
        .tcp_nodelay(true)
        .pool_max_idle_per_host(workers)
        .build()?;
    let url = format!(
        "{}/internal/v1/authorizations",
        issuer_url.trim_end_matches('/')
    );
    let shared = Arc::new(Mutex::new(Shared {
        hist: Histogram::new_with_bounds(1, 60_000_000, 3)?,
        rcs: BTreeMap::new(),
        errors: 0,
    }));
    let recording = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let run_id = format!("{}", chrono::Utc::now().timestamp_millis());
    let mut handles = Vec::new();
    for w in 0..workers {
        let (http, url, shared, recording, stop) = (
            http.clone(),
            url.clone(),
            shared.clone(),
            recording.clone(),
            stop.clone(),
        );
        let targets = targets.clone();
        let run_id = run_id.clone();
        handles.push(tokio::spawn(async move {
            let mut local = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).expect("hist");
            let mut rcs: BTreeMap<String, u64> = BTreeMap::new();
            let mut errors = 0;
            let mut i = 0usize;
            while !stop.load(Ordering::Relaxed) {
                let (card_id, account_id) = targets[(w + i * workers) % targets.len()];
                i += 1;
                let body = serde_json::json!({
                    "authRef": format!("IB-{run_id}-{w}-{i}"), "cardId": card_id, "accountId": account_id,
                    "amountMinor": 100, "currency": "840", "txnType": "PURCHASE", "mcc": "5411",
                    "stan": "000001", "rrn": "000000000001", "terminalId": "BENCH", "merchantId": "M",
                    "merchantName": "BENCH", "entryMode": "051", "transmittedAt": "1002120000"
                });
                let t0 = Instant::now();
                let res = http.post(&url).json(&body).send().await;
                let ok = match res {
                    Ok(r) => r.json::<serde_json::Value>().await.ok(),
                    Err(_) => None,
                };
                let us = t0.elapsed().as_micros() as u64;
                if recording.load(Ordering::Relaxed) {
                    match ok {
                        Some(v) => {
                            let _ = local.record(us.max(1));
                            *rcs.entry(v["responseCode"].as_str().unwrap_or("??").to_string()).or_insert(0) += 1;
                        }
                        None => errors += 1,
                    }
                }
            }
            let mut s = shared.lock().expect("lock");
            let _ = s.hist.add(&local);
            for (k, v) in rcs {
                *s.rcs.entry(k).or_insert(0) += v;
            }
            s.errors += errors;
        }));
    }
    tokio::time::sleep(warmup).await;
    recording.store(true, Ordering::SeqCst);
    let t0 = Instant::now();
    tokio::time::sleep(duration).await;
    recording.store(false, Ordering::SeqCst);
    let elapsed = t0.elapsed().as_secs_f64();
    stop.store(true, Ordering::SeqCst);
    for h in handles {
        let _ = h.await;
    }
    let s = shared.lock().expect("lock");
    let ms = |q: f64| s.hist.value_at_quantile(q) as f64 / 1000.0;
    Ok(BenchResult {
        mode: "issuer-api-direct".into(),
        connections: workers,
        workers,
        duration_s: (elapsed * 10.0).round() / 10.0,
        requests: s.hist.len(),
        throughput_per_s: (s.hist.len() as f64 / elapsed).round(),
        p50_ms: ms(0.5),
        p90_ms: ms(0.9),
        p99_ms: ms(0.99),
        p999_ms: ms(0.999),
        max_ms: s.hist.max() as f64 / 1000.0,
        response_codes: s.rcs.clone(),
        errors: s.errors,
    })
}
