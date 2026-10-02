use anyhow::Context;
use clap::{Parser, Subcommand};
use hdrhistogram::Histogram;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use termsim::cards::{generate_bulk, CardSecret};
use termsim::issuer::Issuer;
use termsim::keys::TestKeys;

#[derive(Parser)]
#[command(about = "Card/terminal simulator: test cards, demo scenario and load generator")]
struct Cli {
    /// Clear PUBLIC TEST keys (personalisation bureau / PIN pad side).
    #[arg(long, default_value = "config/test-keys.toml", global = true)]
    keys: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate load-test cards; optionally import them into the issuer.
    GenCards {
        #[arg(long, default_value_t = 2000)]
        count: usize,
        #[arg(long, default_value = ".run/bench-cards.json")]
        out: String,
        #[arg(long)]
        import_url: Option<String>,
        #[arg(long, default_value_t = 1)]
        seed: u64,
    },
    /// Issue the named demo cards and register them with the issuer.
    DemoSetup {
        #[arg(long, default_value = "http://127.0.0.1:27180")]
        issuer: String,
        #[arg(long, default_value = ".run/demo-cards.json")]
        out: String,
    },
    /// Run the scripted end-to-end scenario and write a transcript.
    Demo {
        #[arg(long, default_value = "127.0.0.1:27583")]
        switch: String,
        #[arg(long, default_value = "http://127.0.0.1:27180")]
        issuer: String,
        #[arg(long, default_value = ".run/demo-cards.json")]
        cards: String,
        #[arg(long, default_value = "docs/demo-transcript.txt")]
        transcript: String,
        /// Control script for the issuer process: `<script> hang|resume|kill|start`.
        #[arg(long, default_value = "scripts/issuer.sh")]
        issuer_ctl: String,
    },
    /// End-to-end load over TCP through the switch.
    Bench {
        #[arg(long, default_value = "127.0.0.1:27583")]
        switch: String,
        #[arg(long, default_value = ".run/bench-cards.json")]
        cards: String,
        #[arg(long, default_value_t = 4)]
        connections: usize,
        #[arg(long, default_value_t = 64)]
        workers: usize,
        #[arg(long, default_value_t = 5)]
        warmup_s: u64,
        #[arg(long, default_value_t = 30)]
        duration_s: u64,
        /// chip-pin | chip | magstripe
        #[arg(long, default_value = "chip-pin")]
        mode: String,
        #[arg(long, default_value_t = 100)]
        amount_minor: i64,
        #[arg(long)]
        out: Option<String>,
    },
    /// Direct load on the issuer's internal authorize API (no switch).
    BenchIssuer {
        #[arg(long, default_value = "http://127.0.0.1:27180")]
        issuer: String,
        #[arg(long, default_value = ".run/bench-cards.json")]
        cards: String,
        #[arg(long, default_value_t = 64)]
        workers: usize,
        #[arg(long, default_value_t = 5)]
        warmup_s: u64,
        #[arg(long, default_value_t = 20)]
        duration_s: u64,
        #[arg(long)]
        out: Option<String>,
    },
    /// Direct load on the HSM (ARQC verify + ARPC, PIN verify), no switch.
    BenchHsm {
        #[arg(long, default_value = "127.0.0.1:27910")]
        hsm: String,
        #[arg(long, default_value = "config/switch.toml")]
        switch_config: String,
        #[arg(long, default_value_t = 64)]
        workers: usize,
        #[arg(long, default_value_t = 20)]
        duration_s: u64,
        #[arg(long)]
        out: Option<String>,
    },
}

#[derive(serde::Serialize, serde::Deserialize)]
struct BenchCard {
    secret: CardSecret,
    card_id: i64,
    account_id: i64,
}

fn write_out(out: &Option<String>, v: &impl serde::Serialize) -> anyhow::Result<()> {
    let s = serde_json::to_string_pretty(v)?;
    println!("{s}");
    if let Some(p) = out {
        std::fs::write(p, s)?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();
    let cli = Cli::parse();
    let keys = TestKeys::load(&cli.keys).with_context(|| format!("loading {}", cli.keys))?;
    match cli.cmd {
        Cmd::GenCards {
            count,
            out,
            import_url,
            seed,
        } => {
            let cards = generate_bulk(&keys, count, 500_000, seed)?;
            let mut ids = vec![(0i64, 0i64); cards.len()];
            if let Some(url) = import_url {
                let recs: Vec<_> = cards.iter().map(|(_, r)| r.clone()).collect();
                let res = Issuer::new(&url).import(&recs).await?;
                for (i, r) in res.iter().enumerate() {
                    ids[i] = (r.card_id, r.account_id);
                }
                println!("imported {} cards into {url}", res.len());
            }
            let file: Vec<BenchCard> = cards
                .into_iter()
                .zip(ids)
                .map(|((secret, _), (card_id, account_id))| BenchCard {
                    secret,
                    card_id,
                    account_id,
                })
                .collect();
            if let Some(dir) = std::path::Path::new(&out).parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(&out, serde_json::to_vec(&file)?)?;
            println!("wrote {} cards to {out}", file.len());
        }
        Cmd::DemoSetup { issuer, out } => {
            if let Some(dir) = std::path::Path::new(&out).parent() {
                std::fs::create_dir_all(dir)?;
            }
            termsim::demo::setup(&keys, &issuer, &out).await?;
        }
        Cmd::Demo {
            switch,
            issuer,
            cards,
            transcript,
            issuer_ctl,
        } => {
            termsim::demo::run(
                keys,
                termsim::demo::DemoOpts {
                    switch_addr: switch,
                    issuer_url: issuer,
                    cards_file: cards,
                    transcript,
                    issuer_ctl,
                },
            )
            .await?;
        }
        Cmd::Bench {
            switch,
            cards,
            connections,
            workers,
            warmup_s,
            duration_s,
            mode,
            amount_minor,
            out,
        } => {
            let file: Vec<BenchCard> = serde_json::from_slice(&std::fs::read(&cards)?)?;
            let secrets = file.into_iter().map(|c| c.secret).collect();
            let r = termsim::bench::run(
                keys,
                secrets,
                termsim::bench::BenchOpts {
                    switch_addr: switch,
                    connections,
                    workers,
                    warmup: Duration::from_secs(warmup_s),
                    duration: Duration::from_secs(duration_s),
                    mode,
                    amount_minor,
                },
            )
            .await?;
            write_out(&out, &r)?;
        }
        Cmd::BenchIssuer {
            issuer,
            cards,
            workers,
            warmup_s,
            duration_s,
            out,
        } => {
            let file: Vec<BenchCard> = serde_json::from_slice(&std::fs::read(&cards)?)?;
            let targets: Vec<(i64, i64)> = file.iter().map(|c| (c.card_id, c.account_id)).collect();
            anyhow::ensure!(
                targets.iter().all(|t| t.0 > 0),
                "cards were not imported (use --import-url)"
            );
            let r = termsim::bench::run_issuer(
                &issuer,
                targets,
                workers,
                Duration::from_secs(warmup_s),
                Duration::from_secs(duration_s),
            )
            .await?;
            write_out(&out, &r)?;
        }
        Cmd::BenchHsm {
            hsm,
            switch_config,
            workers,
            duration_s,
            out,
        } => {
            let r = bench_hsm(
                &keys,
                &hsm,
                &switch_config,
                workers,
                Duration::from_secs(duration_s),
            )
            .await?;
            write_out(&out, &r)?;
        }
    }
    Ok(())
}

/// Each iteration = what the switch asks the HSM for on a chip + PIN
/// transaction: one PIN verification and one ARQC verification with ARPC.
async fn bench_hsm(
    keys: &TestKeys,
    addr: &str,
    switch_config: &str,
    workers: usize,
    duration: Duration,
) -> anyhow::Result<serde_json::Value> {
    use hsm::proto::{ArpcMethod, Command, Reply};
    let cfg: toml::Value = toml::from_str(&std::fs::read_to_string(switch_config)?)?;
    let k = |n: &str| cfg["keys"][n].as_str().unwrap_or_default().to_string();
    let client = Arc::new(hsm::client::HsmClient::connect(addr, 4, Duration::from_secs(5)).await?);
    let cards = generate_bulk(keys, 1, 900_000, 7)?;
    let secret = cards[0].0.clone();
    let mut card = termsim::emvcard::EmvCard::personalise(secret.clone(), keys)?;
    let crypto = card.generate_arqc(100, "840", "261002", 0, [1, 2, 3, 4])?;
    let l = &crypto.tlvs;
    let get = |t: u32| iso8583::tlv::find(l, t).unwrap_or_default().to_vec();
    let mut data = Vec::new();
    for t in [
        0x9F02, 0x9F03, 0x9F1A, 0x95, 0x5F2A, 0x9A, 0x9C, 0x9F37, 0x82, 0x9F36, 0x9F10,
    ] {
        data.extend(get(t));
    }
    let pin_block =
        cardcrypto::pinblock::encrypt_iso0(&TestKeys::key(&keys.zpk), &secret.pin, &secret.pan)?;
    let arqc_cmd = Command::VerifyArqc {
        imk_ac: k("imk_ac"),
        cvn: 18,
        pan: secret.pan.clone(),
        psn: "00".into(),
        atc: hex::encode_upper(crypto.atc),
        data: hex::encode_upper(&data),
        arqc: hex::encode_upper(crypto.arqc),
        arpc: Some(ArpcMethod::Method2 {
            csu: "00800000".into(),
            prop: String::new(),
        }),
    };
    let pin_cmd = Command::VerifyPinPvv {
        zpk: k("zpk"),
        pvk: k("pvk"),
        pin_block: hex::encode_upper(pin_block),
        pan: secret.pan.clone(),
        pvki: keys.pvki,
        pvv: secret.pvv.clone(),
    };
    anyhow::ensure!(
        matches!(
            client.call(arqc_cmd.clone()).await?,
            Reply::Arqc { ok: true, .. }
        ),
        "ARQC self-check failed"
    );
    anyhow::ensure!(
        client.call(pin_cmd.clone()).await? == Reply::Verified { ok: true },
        "PIN self-check failed"
    );
    let hist = Arc::new(Mutex::new(Histogram::<u64>::new_with_bounds(
        1, 60_000_000, 3,
    )?));
    let stop = Arc::new(AtomicBool::new(false));
    let mut hs = Vec::new();
    for _ in 0..workers {
        let (client, hist, stop) = (client.clone(), hist.clone(), stop.clone());
        let (a, p) = (arqc_cmd.clone(), pin_cmd.clone());
        hs.push(tokio::spawn(async move {
            let mut local = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).expect("hist");
            while !stop.load(Ordering::Relaxed) {
                let t0 = Instant::now();
                let _ = client.call(p.clone()).await;
                let _ = client.call(a.clone()).await;
                let _ = local.record((t0.elapsed().as_micros() as u64).max(1));
            }
            let _ = hist.lock().expect("lock").add(&local);
        }));
    }
    let t0 = Instant::now();
    tokio::time::sleep(duration).await;
    stop.store(true, Ordering::SeqCst);
    for h in hs {
        let _ = h.await;
    }
    let el = t0.elapsed().as_secs_f64();
    let h = hist.lock().expect("lock");
    let ms = |q: f64| h.value_at_quantile(q) as f64 / 1000.0;
    Ok(serde_json::json!({
        "mode": "hsm-direct (PIN verify + ARQC verify/ARPC per iteration)",
        "workers": workers,
        "iterations": h.len(),
        "iterations_per_s": (h.len() as f64 / el).round(),
        "p50_ms": ms(0.5), "p99_ms": ms(0.99), "max_ms": h.max() as f64 / 1000.0
    }))
}
