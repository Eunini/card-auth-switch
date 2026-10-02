//! End-to-end tests over TCP: terminal simulator -> switch -> real HSM
//! process logic (in-process server) -> mock issuer.

use futures::future::BoxFuture;
use hsm::keyblock::Lmk;
use hsm::proto::KeyType;
use iso8583::{tlv, Message, Mti};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use switch::cards::CardProfile;
use switch::config::*;
use switch::issuer::*;
use termsim::cards::{issue, CardSecret, CardSpec, IssuerCardRecord};
use termsim::client::AcquirerClient;
use termsim::emvcard::EmvCard;
use termsim::keys::TestKeys;
use termsim::terminal::{Entry, Terminal, TxnOpts};

const LMK: &str = "29AD24DCEA8A5E67B35AE917A6E57F51457A9BBCDD9CE5D2C34403E0E0AE73B8";

#[derive(Default)]
struct MockIssuer {
    down: AtomicBool,
    balances: Mutex<HashMap<i64, i64>>,
    holds: Mutex<HashMap<String, (i64, i64)>>, // auth_ref -> (account, amount)
    cards: Mutex<Vec<CardProfile>>,
    advices: Mutex<Vec<AdviceRequest>>,
    reversals: Mutex<Vec<ReversalRequest>>,
}

impl MockIssuer {
    fn check(&self) -> Result<(), IssuerError> {
        if self.down.load(Ordering::SeqCst) {
            Err(IssuerError::Unavailable("connection refused".into()))
        } else {
            Ok(())
        }
    }
}

impl IssuerApi for MockIssuer {
    fn authorize(&self, r: AuthRequest) -> BoxFuture<'_, Result<AuthResponse, IssuerError>> {
        Box::pin(async move {
            self.check()?;
            let mut b = self.balances.lock().unwrap();
            let bal = b.entry(r.account_id).or_insert(0);
            if *bal < r.amount_minor {
                return Ok(AuthResponse {
                    approved: false,
                    response_code: "51".into(),
                    auth_code: None,
                    available_minor: Some(*bal),
                });
            }
            *bal -= r.amount_minor;
            self.holds
                .lock()
                .unwrap()
                .insert(r.auth_ref.clone(), (r.account_id, r.amount_minor));
            Ok(AuthResponse {
                approved: true,
                response_code: "00".into(),
                auth_code: Some("A12345".into()),
                available_minor: Some(*bal),
            })
        })
    }
    fn advice(&self, r: AdviceRequest) -> BoxFuture<'_, Result<AckResponse, IssuerError>> {
        Box::pin(async move {
            self.check()?;
            self.advices.lock().unwrap().push(r);
            Ok(AckResponse {
                status: "RECORDED".into(),
            })
        })
    }
    fn reverse(&self, r: ReversalRequest) -> BoxFuture<'_, Result<ReversalResponse, IssuerError>> {
        Box::pin(async move {
            self.check()?;
            self.reversals.lock().unwrap().push(r.clone());
            let status = match self.holds.lock().unwrap().remove(&r.auth_ref) {
                Some((acct, amt)) => {
                    *self.balances.lock().unwrap().entry(acct).or_insert(0) += amt;
                    "REVERSED"
                }
                None => "NOT_FOUND",
            };
            Ok(ReversalResponse {
                status: status.into(),
            })
        })
    }
    fn card_snapshot(&self) -> BoxFuture<'_, Result<Vec<CardProfile>, IssuerError>> {
        Box::pin(async move {
            self.check()?;
            Ok(self.cards.lock().unwrap().clone())
        })
    }
    fn health(&self) -> BoxFuture<'_, Result<(), IssuerError>> {
        Box::pin(async move { self.check() })
    }
}

struct Env {
    addr: String,
    issuer: Arc<MockIssuer>,
    sw: Arc<switch::engine::Switch>,
    keys: TestKeys,
    _dir: tempfile::TempDir,
}

fn profile(i: i64, r: &IssuerCardRecord) -> CardProfile {
    CardProfile {
        card_id: i,
        account_id: 100 + i,
        pan_ref: r.pan_ref.clone(),
        last4: r.last4.clone(),
        expiry: r.expiry.clone(),
        status: r.status.clone(),
        pvv: r.pvv.clone(),
        pvki: r.pvki,
        service_code: r.service_code.clone(),
        psn: r.psn.clone(),
        cvn: r.cvn,
        currency: r.currency.clone(),
        per_txn_limit_minor: r.per_txn_limit_minor,
        daily_cash_limit_minor: r.daily_cash_limit_minor,
        daily_txn_count_limit: r.daily_txn_count_limit,
    }
}

async fn setup(specs: &[CardSpec]) -> (Env, Vec<CardSecret>) {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/test-keys.toml");
    let keys = TestKeys::load(root).unwrap();
    let lmk = Lmk::from_hex(LMK).unwrap();

    let hl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hsm_addr = hl.local_addr().unwrap().to_string();
    tokio::spawn(hsm::server::serve(
        hl,
        Arc::new(hsm::server::Hsm::new(Lmk::from_hex(LMK).unwrap(), false)),
    ));

    let issuer = Arc::new(MockIssuer::default());
    let mut rng = rand::thread_rng();
    let mut secrets = Vec::new();
    for (i, s) in specs.iter().enumerate() {
        let (secret, rec) = issue(&keys, 7000 + i as u64, s, &mut rng).unwrap();
        issuer
            .cards
            .lock()
            .unwrap()
            .push(profile(i as i64 + 1, &rec));
        issuer
            .balances
            .lock()
            .unwrap()
            .insert(101 + i as i64, s.opening_balance_minor);
        secrets.push(secret);
    }

    let dir = tempfile::tempdir().unwrap();
    let cfg = Config {
        listen: "127.0.0.1:0".into(),
        idle_timeout_secs: 30,
        max_in_flight_per_conn: 64,
        hsm_addr,
        hsm_pool: 2,
        hsm_timeout_ms: 2000,
        issuer_url: "mock".into(),
        issuer_timeout_ms: 200,
        card_refresh_secs: 3600,
        card_snapshot_file: dir.path().join("cards.json").to_string_lossy().into(),
        stip_journal: dir.path().join("saf.log").to_string_lossy().into(),
        pan_hmac_key: keys.pan_hmac.clone(),
        keys: Keys {
            zpk: lmk.wrap(KeyType::Zpk, &TestKeys::key(&keys.zpk)),
            pvk: lmk.wrap(KeyType::Pvk, &TestKeys::key(&keys.pvk)),
            cvk: lmk.wrap(KeyType::Cvk, &TestKeys::key(&keys.cvk)),
            imk_ac: lmk.wrap(KeyType::ImkAc, &TestKeys::key(&keys.imk_ac)),
        },
        stand_in: StandIn {
            per_txn_limit_minor: 10_000,
            daily_limit_minor: 15_000,
        },
        circuit: Circuit {
            failure_threshold: 2,
            open_ms: 100_000,
        },
    };
    let sw = switch::build(cfg, issuer.clone()).await.unwrap();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    tokio::spawn(switch::server::serve(l, sw.clone()));
    (
        Env {
            addr,
            issuer,
            sw,
            keys,
            _dir: dir,
        },
        secrets,
    )
}

fn rc(m: &Message) -> &str {
    m.get_str(39).unwrap_or("??")
}

fn tag91(m: &Message) -> Option<Vec<u8>> {
    let l = tlv::parse(m.get(55)?).ok()?;
    tlv::find(&l, 0x91).map(<[u8]>::to_vec)
}

async fn signed_on(env: &Env, tid: &str) -> (AcquirerClient, Terminal) {
    let c = AcquirerClient::connect(&env.addr).await.unwrap();
    let mut t = Terminal::new(tid, &env.keys);
    let (r, _) = c.send(&t.sign_on()).await.unwrap();
    assert_eq!(rc(&r), "00");
    (c, t)
}

#[tokio::test]
async fn sign_on_is_required_and_echo_works() {
    let (env, secrets) = setup(&[CardSpec::standard("A", 18, 100_000)]).await;
    let c = AcquirerClient::connect(&env.addr).await.unwrap();
    let mut t = Terminal::new("T1", &env.keys);
    let mut card = EmvCard::personalise(secrets[0].clone(), &env.keys).unwrap();
    let b = t
        .auth(&mut card, 1000, &TxnOpts::chip_pin(&secrets[0].pin))
        .unwrap();
    let (r, _) = c.send(&b.msg).await.unwrap();
    assert_eq!(rc(&r), "58", "financial message before sign-on");
    let (r, _) = c.send(&t.sign_on()).await.unwrap();
    assert_eq!((r.mti, rc(&r)), (Mti::NETWORK_RESPONSE, "00"));
    let (r, _) = c.send(&t.echo()).await.unwrap();
    assert_eq!(rc(&r), "00");
}

#[tokio::test]
async fn chip_and_pin_happy_path_and_declines() {
    let mut low = CardSpec::standard("Low", 10, 500);
    low.cvn = 10;
    let mut lost = CardSpec::standard("Lost", 18, 100_000);
    lost.status = "LOST".into();
    let mut expired = CardSpec::standard("Old", 18, 100_000);
    expired.expiry = "2001".into();
    let (env, s) = setup(&[CardSpec::standard("A", 18, 100_000), low, lost, expired]).await;
    let (c, mut t) = signed_on(&env, "T2").await;

    // Approved, with an ARPC the card accepts (CVN 18, method 2).
    let mut a = EmvCard::personalise(s[0].clone(), &env.keys).unwrap();
    let b = t.auth(&mut a, 4250, &TxnOpts::chip_pin(&s[0].pin)).unwrap();
    let (r, _) = c.send(&b.msg).await.unwrap();
    assert_eq!(rc(&r), "00");
    assert_eq!(r.get_str(38), Some("A12345"));
    assert!(a.verify_arpc(b.cryptogram.as_ref().unwrap(), &tag91(&r).unwrap()));

    // Retransmission of the same request: same answer, no second hold.
    let (r2, _) = c.send(&b.msg).await.unwrap();
    assert_eq!(r2, r);
    assert_eq!(env.issuer.holds.lock().unwrap().len(), 1);

    // ATC replay: resend a cryptogram with a new STAN (fresh message, old ATC).
    let mut replay = b.msg.clone();
    replay.set(11, "999999");
    let (r, _) = c.send(&replay).await.unwrap();
    assert_eq!(rc(&r), "82");

    // Wrong PIN, then tries exceeded.
    let wrong = if s[0].pin == "0000" { "1111" } else { "0000" };
    for expect in ["55", "55", "55", "75"] {
        let b = t.auth(&mut a, 100, &TxnOpts::chip_pin(wrong)).unwrap();
        let (r, _) = c.send(&b.msg).await.unwrap();
        assert_eq!(rc(&r), expect);
    }

    // Tampered ARQC on a CVN 10 card.
    let mut low = EmvCard::personalise(s[1].clone(), &env.keys).unwrap();
    let mut o = TxnOpts::chip_pin(&s[1].pin);
    o.tamper_arqc = true;
    let (r, _) = c
        .send(&t.auth(&mut low, 100, &o).unwrap().msg)
        .await
        .unwrap();
    assert_eq!(rc(&r), "82");
    assert!(tag91(&r).is_none(), "no ARPC for a forged cryptogram");

    // Insufficient funds: decline comes with a *decline* ARPC (ARC "51").
    let b = t
        .auth(&mut low, 9_999, &TxnOpts::chip_pin(&s[1].pin))
        .unwrap();
    let (r, _) = c.send(&b.msg).await.unwrap();
    assert_eq!(rc(&r), "51");
    let t91 = tag91(&r).unwrap();
    assert_eq!(&t91[8..], b"51");
    assert!(low.verify_arpc(b.cryptogram.as_ref().unwrap(), &t91));

    // Lost card, expired card, unknown card.
    let mut lost = EmvCard::personalise(s[2].clone(), &env.keys).unwrap();
    let (r, _) = c
        .send(
            &t.auth(&mut lost, 100, &TxnOpts::chip_pin(&s[2].pin))
                .unwrap()
                .msg,
        )
        .await
        .unwrap();
    assert_eq!(rc(&r), "41");
    let mut old = EmvCard::personalise(s[3].clone(), &env.keys).unwrap();
    let (r, _) = c
        .send(
            &t.auth(&mut old, 100, &TxnOpts::chip_pin(&s[3].pin))
                .unwrap()
                .msg,
        )
        .await
        .unwrap();
    assert_eq!(rc(&r), "54");
    let mut ghost = s[0].clone();
    ghost.pan = "9990019999999995".into();
    let mut ghost = EmvCard::personalise(ghost, &env.keys).unwrap();
    let (r, _) = c
        .send(
            &t.auth(&mut ghost, 100, &TxnOpts::chip_pin("1234"))
                .unwrap()
                .msg,
        )
        .await
        .unwrap();
    assert_eq!(rc(&r), "14");
}

#[tokio::test]
async fn magstripe_cvv_and_cash_pin_rule() {
    let (env, s) = setup(&[CardSpec::standard("M", 18, 100_000)]).await;
    let (c, mut t) = signed_on(&env, "T3").await;
    let mut card = EmvCard::personalise(s[0].clone(), &env.keys).unwrap();
    let mut o = TxnOpts::chip_pin(&s[0].pin);
    o.entry = Entry::Magstripe;
    o.pin = None;
    let (r, _) = c
        .send(&t.auth(&mut card, 700, &o).unwrap().msg)
        .await
        .unwrap();
    assert_eq!(rc(&r), "00");

    // Corrupt the CVV inside track 2.
    let mut b = t.auth(&mut card, 700, &o).unwrap().msg;
    let t2 = b.get_str(35).unwrap().to_string();
    let i = t2.find('=').unwrap() + 13; // = | YYMM SSS P VVVV [CVV]
    let mut chars: Vec<char> = t2.chars().collect();
    chars[i] = if chars[i] == '9' { '0' } else { '9' };
    b.set(35, chars.into_iter().collect::<String>());
    let (r, _) = c.send(&b).await.unwrap();
    assert_eq!(rc(&r), "82");

    // Cash without PIN is refused; with PIN it is a 0200 approved.
    let mut cash = TxnOpts::chip_pin(&s[0].pin);
    cash.cash = true;
    cash.pin = None;
    let (r, _) = c
        .send(&t.auth(&mut card, 2000, &cash).unwrap().msg)
        .await
        .unwrap();
    assert_eq!(rc(&r), "55");
    cash.pin = Some(s[0].pin.clone());
    let (r, _) = c
        .send(&t.auth(&mut card, 2000, &cash).unwrap().msg)
        .await
        .unwrap();
    assert_eq!((r.mti, rc(&r)), (Mti::FIN_RESPONSE, "00"));
}

#[tokio::test]
async fn reversal_is_idempotent_and_matches_original() {
    let (env, s) = setup(&[CardSpec::standard("R", 18, 100_000)]).await;
    let (c, mut t) = signed_on(&env, "T4").await;
    let mut card = EmvCard::personalise(s[0].clone(), &env.keys).unwrap();
    let b = t
        .auth(&mut card, 5000, &TxnOpts::chip_pin(&s[0].pin))
        .unwrap();
    let (r, _) = c.send(&b.msg).await.unwrap();
    assert_eq!(rc(&r), "00");
    assert_eq!(env.issuer.balances.lock().unwrap()[&101], 95_000);

    let rev = t.reversal(&b.msg, None, false);
    let (r, _) = c.send(&rev).await.unwrap();
    assert_eq!((r.mti, rc(&r)), (Mti::REVERSAL_RESPONSE, "00"));
    // Repeat (0401) and a retransmitted reversal: no second issuer call.
    let (r, _) = c.send(&Terminal::as_repeat(&rev)).await.unwrap();
    assert_eq!(rc(&r), "00");
    assert_eq!(env.issuer.reversals.lock().unwrap().len(), 1);
    assert_eq!(env.issuer.balances.lock().unwrap()[&101], 100_000);

    // Reversal of something never seen: 25 for a request...
    let mut other = b.msg.clone();
    other.set(11, "123450").set(37, "000000999999");
    let (r, _) = c.send(&t.reversal(&other, None, false)).await.unwrap();
    assert_eq!(rc(&r), "25");
    // ... and the late original is then refused.
    let (r, _) = c.send(&other).await.unwrap();
    assert_eq!(rc(&r), "05");
}

#[tokio::test]
async fn stand_in_then_store_and_forward_replay() {
    let (env, s) = setup(&[CardSpec::standard("S", 18, 100_000)]).await;
    let (c, mut t) = signed_on(&env, "T5").await;
    let mut card = EmvCard::personalise(s[0].clone(), &env.keys).unwrap();

    env.issuer.down.store(true, Ordering::SeqCst);
    // Within stand-in limits: approved by the switch, marked STIP, ARPC still valid.
    let b = t
        .auth(&mut card, 6000, &TxnOpts::chip_pin(&s[0].pin))
        .unwrap();
    let (r, _) = c.send(&b.msg).await.unwrap();
    assert_eq!(rc(&r), "00");
    assert_eq!(r.get_str(44), Some("STIP"));
    assert!(r.get_str(38).unwrap().starts_with('S'));
    assert!(card.verify_arpc(b.cryptogram.as_ref().unwrap(), &tag91(&r).unwrap()));
    // Above the per-transaction stand-in limit: 91.
    let (r, _) = c
        .send(
            &t.auth(&mut card, 20_000, &TxnOpts::chip_pin(&s[0].pin))
                .unwrap()
                .msg,
        )
        .await
        .unwrap();
    assert_eq!(rc(&r), "91");
    // Cumulative stand-in limit (15000): 6000 + 9000 ok, then 100 more is refused.
    let (r, _) = c
        .send(
            &t.auth(&mut card, 9_000, &TxnOpts::chip_pin(&s[0].pin))
                .unwrap()
                .msg,
        )
        .await
        .unwrap();
    assert_eq!(rc(&r), "00");
    let (r, _) = c
        .send(
            &t.auth(&mut card, 100, &TxnOpts::chip_pin(&s[0].pin))
                .unwrap()
                .msg,
        )
        .await
        .unwrap();
    assert_eq!(rc(&r), "91");
    // Reverse the first stand-in approval while the issuer is still down.
    let (r, _) = c.send(&t.reversal(&b.msg, None, true)).await.unwrap();
    assert_eq!((r.mti, rc(&r)), (Mti::REVERSAL_ADVICE_RESPONSE, "00"));

    assert!(env.sw.circuit.is_open());
    assert_eq!(
        env.sw.journal.pending_len(),
        5,
        "4 advices + 1 reversal queued"
    );
    assert!(env.issuer.advices.lock().unwrap().is_empty());

    // Recovery: replay in order.
    env.issuer.down.store(false, Ordering::SeqCst);
    let sent = env.sw.replay_saf().await;
    assert_eq!(sent, 5);
    assert_eq!(env.sw.journal.pending_len(), 0);
    let adv = env.issuer.advices.lock().unwrap();
    assert_eq!(adv.len(), 4);
    assert_eq!(
        adv.iter()
            .map(|a| a.response_code.as_str())
            .collect::<Vec<_>>(),
        vec!["00", "91", "00", "91"]
    );
    assert!(adv.iter().all(|a| a.source == "SWITCH_STIP"));
    assert_eq!(env.issuer.reversals.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn malformed_frame_gets_format_error() {
    let (env, _) = setup(&[CardSpec::standard("F", 18, 1)]).await;
    use futures::{SinkExt, StreamExt};
    let sock = tokio::net::TcpStream::connect(&env.addr).await.unwrap();
    let mut f = tokio_util::codec::Framed::new(sock, switch::server::codec());
    f.send(bytes::Bytes::from_static(
        b"0100\x40\x00\x00\x00\x00\x00\x00\x0099",
    ))
    .await
    .unwrap();
    let resp = f.next().await.unwrap().unwrap();
    let m = Message::decode(&iso8583::Spec::v1987_ascii(), &resp).unwrap();
    assert_eq!((m.mti, rc(&m)), (Mti::AUTH_RESPONSE, "30"));
}

#[tokio::test]
async fn concurrent_load_on_one_connection() {
    let specs: Vec<CardSpec> = (0..20)
        .map(|i| CardSpec::standard(&format!("L{i}"), 18, 10_000_000))
        .collect();
    let (env, s) = setup(&specs).await;
    let c = Arc::new(AcquirerClient::connect(&env.addr).await.unwrap());
    let mut t0 = Terminal::new("TL", &env.keys);
    c.send(&t0.sign_on()).await.unwrap();
    let mut hs = Vec::new();
    for (i, secret) in s.into_iter().enumerate() {
        let c = c.clone();
        let keys = env.keys.clone();
        hs.push(tokio::spawn(async move {
            let mut t = Terminal::new(&format!("TL{i:03}"), &keys);
            let mut card = EmvCard::personalise(secret.clone(), &keys).unwrap();
            for _ in 0..10 {
                let b = t
                    .auth(&mut card, 100, &TxnOpts::chip_pin(&secret.pin))
                    .unwrap();
                let (r, _) = c.send(&b.msg).await.unwrap();
                assert_eq!(rc(&r), "00");
            }
        }));
    }
    for h in hs {
        h.await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(env.issuer.holds.lock().unwrap().len(), 200);
}
