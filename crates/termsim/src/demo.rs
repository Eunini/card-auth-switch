//! Scripted end-to-end scenario producing a readable transcript.

use crate::cards::{issue, CardSecret, CardSpec};
use crate::clearing::{self, Record};
use crate::client::AcquirerClient;
use crate::emvcard::{Cryptogram, EmvCard};
use crate::issuer::Issuer;
use crate::keys::TestKeys;
use crate::terminal::{Entry, Terminal, TxnOpts};
use anyhow::Context;
use chrono::Utc;
use iso8583::{mask_pan, tlv, Message, Spec};
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::Write;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoCard {
    pub secret: CardSecret,
    pub card_id: i64,
    pub account_id: i64,
}

/// Issue the demo cards and register them with the issuer back office.
pub async fn setup(keys: &TestKeys, issuer_url: &str, out: &str) -> anyhow::Result<()> {
    let mut rng = rand::rngs::StdRng::seed_from_u64(20261002);
    let mut lost = CardSpec::standard("Dave (reported lost)", 18, 10_000);
    lost.status = "LOST".into();
    let specs = [
        CardSpec::standard("Alice", 18, 50_000),
        CardSpec::standard("Bob", 10, 2_000),
        CardSpec::standard("Carol", 18, 30_000),
        lost,
    ];
    let mut issued = Vec::new();
    for (i, s) in specs.iter().enumerate() {
        issued.push(issue(keys, 100 + i as u64, s, &mut rng)?);
    }
    let records: Vec<_> = issued.iter().map(|(_, r)| r.clone()).collect();
    let ids = Issuer::new(issuer_url).import(&records).await?;
    let cards: Vec<DemoCard> = issued
        .into_iter()
        .zip(ids)
        .map(|((secret, _), id)| DemoCard {
            secret,
            card_id: id.card_id,
            account_id: id.account_id,
        })
        .collect();
    std::fs::write(out, serde_json::to_vec_pretty(&cards)?)?;
    println!("issued {} demo cards -> {out}", cards.len());
    Ok(())
}

pub struct DemoOpts {
    pub switch_addr: String,
    pub issuer_url: String,
    pub cards_file: String,
    pub transcript: String,
    /// Script taking hang | resume | kill | start.
    pub issuer_ctl: String,
}

struct T {
    out: Vec<String>,
    step: u32,
}

impl T {
    fn line(&mut self, s: impl AsRef<str>) {
        println!("{}", s.as_ref());
        self.out.push(s.as_ref().to_string());
    }
    fn h(&mut self, title: &str) {
        self.step += 1;
        self.line("");
        self.line(format!("== {}. {} ==", self.step, title));
    }
    fn block(&mut self, s: &str) {
        for l in s.lines() {
            self.line(format!("     {l}"));
        }
    }
}

fn rc_text(rc: &str) -> &'static str {
    match rc {
        "00" => "approved",
        "05" => "do not honor",
        "14" => "invalid card number",
        "25" => "unable to locate original",
        "30" => "format error",
        "41" => "lost card, pick up",
        "51" => "insufficient funds",
        "54" => "expired card",
        "55" => "incorrect PIN",
        "61" => "exceeds amount limit",
        "65" => "exceeds frequency limit",
        "75" => "PIN tries exceeded",
        "82" => "cryptogram/CVV check failed",
        "91" => "issuer unavailable",
        "94" => "duplicate transmission",
        "96" => "system malfunction",
        _ => "",
    }
}

fn money(minor: i64) -> String {
    let sign = if minor < 0 { "-" } else { "" };
    format!("{sign}${}.{:02}", minor.abs() / 100, minor.abs() % 100)
}

fn summarize_request(m: &Message, c: Option<&Cryptogram>) -> String {
    if let Some(code) = m.get_str(70) {
        let what = match code {
            "001" => "sign-on",
            "002" => "sign-off",
            "301" => "echo test",
            _ => "network management",
        };
        return format!(
            "-> {} STAN {} F070={code} ({what})",
            m.mti,
            m.get_str(11).unwrap_or("-")
        );
    }
    let amount = m
        .get_str(4)
        .and_then(|a| a.parse::<i64>().ok())
        .unwrap_or(0);
    let mut s = format!(
        "-> {} STAN {} {} {} entry {}",
        m.mti,
        m.get_str(11).unwrap_or("-"),
        mask_pan(m.get_str(2).unwrap_or("")),
        money(amount),
        m.get_str(22).unwrap_or("-"),
    );
    if m.has(52) {
        s.push_str(" +PIN");
    }
    if let Some(c) = c {
        s.push_str(&format!(
            " ARQC {} ATC {}",
            hex::encode_upper(c.arqc),
            u16::from_be_bytes(c.atc)
        ));
    }
    if m.has(90) {
        s.push_str(&format!(
            " orig STAN {}",
            &m.get_str(90).unwrap_or("")[4..10]
        ));
    }
    if let Some(f95) = m.get_str(95) {
        s.push_str(&format!(
            " replacement {}",
            money(f95[..12].parse().unwrap_or(0))
        ));
    }
    s
}

fn tag91(m: &Message) -> Option<Vec<u8>> {
    let l = tlv::parse(m.get(55)?).ok()?;
    tlv::find(&l, 0x91).map(<[u8]>::to_vec)
}

struct Ctx {
    t: T,
    client: AcquirerClient,
    issuer: Issuer,
}

impl Ctx {
    async fn send(
        &mut self,
        m: &Message,
        card: Option<&EmvCard>,
        c: Option<&Cryptogram>,
    ) -> anyhow::Result<Message> {
        self.t.line(summarize_request(m, c));
        let (r, took) = self.client.send(m).await?;
        let rc = r.get_str(39).unwrap_or("??");
        let mut s = format!(
            "<- {} RC {rc} ({}) in {:.1} ms",
            r.mti,
            rc_text(rc),
            took.as_secs_f64() * 1000.0
        );
        if let Some(a) = r.get_str(38) {
            s.push_str(&format!(" auth code {a}"));
        }
        if r.get_str(44) == Some("STIP") {
            s.push_str(" [STAND-IN]");
        }
        self.t.line(s);
        if let (Some(card), Some(c)) = (card, c) {
            match tag91(&r) {
                Some(t91) => {
                    let ok = card.verify_arpc(c, &t91);
                    self.t.line(format!(
                        "   card checks ARPC (tag 91 = {}): {}",
                        hex::encode_upper(&t91),
                        if ok {
                            "issuer authenticated"
                        } else {
                            "ARPC INVALID"
                        }
                    ));
                }
                None => self
                    .t
                    .line("   no ARPC in response (cryptogram was not accepted)"),
            }
        }
        Ok(r)
    }

    async fn purchase(
        &mut self,
        term: &mut Terminal,
        card: &mut EmvCard,
        amount: i64,
        o: &TxnOpts,
    ) -> anyhow::Result<(Message, Message)> {
        let b = term.auth(card, amount, o)?;
        let r = self.send(&b.msg, Some(card), b.cryptogram.as_ref()).await?;
        Ok((b.msg, r))
    }

    async fn account(&mut self, label: &str, id: i64) -> anyhow::Result<Value> {
        let v = self.issuer.get(&format!("/api/v1/accounts/{id}")).await?;
        self.t.line(format!(
            "   {label}: ledger {} held {} available {}",
            money(v["ledgerBalanceMinor"].as_i64().unwrap_or(0)),
            money(v["heldMinor"].as_i64().unwrap_or(0)),
            money(v["availableMinor"].as_i64().unwrap_or(0)),
        ));
        Ok(v)
    }
}

fn find(cards: &[DemoCard], name: &str) -> DemoCard {
    cards
        .iter()
        .find(|c| c.secret.name.starts_with(name))
        .cloned()
        .expect("demo card")
}

fn auth_ref(m: &Message) -> String {
    format!(
        "{}-{}-{}-{}",
        m.get_str(41).unwrap_or("").trim(),
        &m.get_str(7).unwrap_or("0000")[..4],
        m.get_str(11).unwrap_or(""),
        m.get_str(37).unwrap_or("").trim()
    )
}

async fn issuer_ctl(t: &mut T, ctl: &str, action: &str) -> anyhow::Result<()> {
    let cmd = format!("{ctl} {action}");
    t.line(format!("   $ scripts/issuer.sh {action}"));
    shell(&cmd).await
}

/// Wait until the issuer shows each auth_ref as a hold with the given approval code.
async fn wait_holds(
    issuer: &Issuer,
    account: i64,
    expect: &[(String, String)],
) -> anyhow::Result<()> {
    let t0 = Instant::now();
    loop {
        if let Ok(v) = issuer.get(&format!("/api/v1/accounts/{account}")).await {
            let holds = v["holds"].as_array().cloned().unwrap_or_default();
            let ok = expect.iter().all(|(r, code)| {
                holds
                    .iter()
                    .any(|h| h["authRef"] == r.as_str() && h["authCode"] == code.as_str())
            });
            if ok {
                return Ok(());
            }
        }
        anyhow::ensure!(
            t0.elapsed() < Duration::from_secs(60),
            "issuer did not reconcile {expect:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn show_holds(x: &mut Ctx, label: &str, account: i64) -> anyhow::Result<()> {
    let v = x.account(label, account).await?;
    for h in v["holds"].as_array().into_iter().flatten() {
        x.t.line(format!(
            "     hold {:<34} {:>8} held {:>8} code {:<6} {:<10} {}",
            h["authRef"].as_str().unwrap_or(""),
            money(h["amountMinor"].as_i64().unwrap_or(0)),
            money(h["heldMinor"].as_i64().unwrap_or(0)),
            h["authCode"].as_str().unwrap_or(""),
            h["status"].as_str().unwrap_or(""),
            h["source"].as_str().unwrap_or("")
        ));
    }
    Ok(())
}

async fn shell(cmd: &str) -> anyhow::Result<()> {
    let st = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .status()
        .await?;
    anyhow::ensure!(st.success(), "command failed: {cmd}");
    Ok(())
}

pub async fn run(keys: TestKeys, o: DemoOpts) -> anyhow::Result<()> {
    let cards: Vec<DemoCard> = serde_json::from_slice(
        &std::fs::read(&o.cards_file).with_context(|| format!("reading {}", o.cards_file))?,
    )?;
    let mut x = Ctx {
        t: T {
            out: Vec::new(),
            step: 0,
        },
        client: AcquirerClient::connect(&o.switch_addr).await?,
        issuer: Issuer::new(&o.issuer_url),
    };
    let (alice, bob, carol, dave) = (
        find(&cards, "Alice"),
        find(&cards, "Bob"),
        find(&cards, "Carol"),
        find(&cards, "Dave"),
    );
    let mut a = EmvCard::personalise(alice.secret.clone(), &keys)?;
    let mut b = EmvCard::personalise(bob.secret.clone(), &keys)?;
    let mut c = EmvCard::personalise(carol.secret.clone(), &keys)?;
    let mut d = EmvCard::personalise(dave.secret.clone(), &keys)?;
    let mut term = Terminal::new("POS00001", &keys).with_stan(100);
    let spec = Spec::v1987_ascii();

    x.t.line("card-auth-switch demo transcript");
    x.t.line(format!(
        "generated {} UTC by `scripts/demo.sh`",
        Utc::now().format("%Y-%m-%d %H:%M:%S")
    ));
    x.t.line("acquirer terminal POS00001 -> switch (ISO 8583:1987 over TCP) -> simulated HSM + issuer back office");
    x.t.line("All cards, keys and amounts are test data. PANs are masked in this transcript.");

    x.t.h("Test cards (issued by the simulator's personalisation step)");
    for card in &cards {
        x.t.line(format!(
            "   {:<22} {}  CVN {}  account #{}",
            card.secret.name,
            mask_pan(&card.secret.pan),
            card.secret.cvn,
            card.account_id
        ));
    }

    x.t.h("Network management: sign-on and echo test (0800/0810)");
    let m = term.sign_on();
    x.send(&m, None, None).await?;
    let m = term.echo();
    x.send(&m, None, None).await?;

    x.t.h("Alice: chip + PIN purchase $42.50 (CVN 18, EMV common session key)");
    let chip = TxnOpts::chip_pin(&alice.secret.pin);
    let b1 = term.auth(&mut a, 4250, &chip)?;
    x.t.line("   request as sent (sensitive fields masked):");
    x.t.block(&b1.msg.describe(&spec));
    let a1_resp = x.send(&b1.msg, Some(&a), b1.cryptogram.as_ref()).await?;
    x.t.line("   response:");
    x.t.block(&a1_resp.describe(&spec));
    let a1_req = b1.msg.clone();
    x.account("Alice", alice.account_id).await?;

    x.t.h("Acquirer retransmits the same 0100 (lost response): switch replays, no second hold");
    x.send(&a1_req, None, None).await?;
    x.account("Alice", alice.account_id).await?;

    x.t.h("Alice: wrong PIN");
    x.purchase(
        &mut term,
        &mut a,
        1999,
        &TxnOpts::chip_pin(if alice.secret.pin == "0000" {
            "1111"
        } else {
            "0000"
        }),
    )
    .await?;

    x.t.h("Alice: second purchase $120.00, then the terminal reverses it (0400), then repeats the reversal (0401)");
    let (a2_req, _) = x.purchase(&mut term, &mut a, 12000, &chip).await?;
    x.account("Alice", alice.account_id).await?;
    let rev = term.reversal(&a2_req, None, false);
    x.send(&rev, None, None).await?;
    x.send(&Terminal::as_repeat(&rev), None, None).await?;
    x.account("Alice", alice.account_id).await?;

    x.t.h("Bob: forged cryptogram (ARQC bit flipped after the card computed it), CVN 10 card");
    let mut forged = TxnOpts::chip_pin(&bob.secret.pin);
    forged.tamper_arqc = true;
    x.purchase(&mut term, &mut b, 1500, &forged).await?;

    x.t.h("Bob: $75.00 with only $20.00 available");
    x.purchase(&mut term, &mut b, 7500, &TxnOpts::chip_pin(&bob.secret.pin))
        .await?;
    x.t.line(
        "   (a decline still carries an ARPC, with ARC = '51', so the card can trust the decline)",
    );

    x.t.h("Dave: card reported lost");
    x.purchase(
        &mut term,
        &mut d,
        2500,
        &TxnOpts::chip_pin(&dave.secret.pin),
    )
    .await?;

    x.t.h("Carol: magnetic stripe fallback $15.00 (CVV in track 2 verified by the HSM)");
    let mut mag = TxnOpts::chip_pin(&carol.secret.pin);
    mag.entry = Entry::Magstripe;
    mag.pin = None;
    let (c1_req, c1_resp) = x.purchase(&mut term, &mut c, 1500, &mag).await?;

    x.t.h("Carol: $50.00 fuel pre-authorization, partially reversed to the $30.00 actually pumped (F95)");
    let mut fuel = TxnOpts::chip_pin(&carol.secret.pin);
    fuel.mcc = "5542".into();
    let (c2_req, c2_resp) = x.purchase(&mut term, &mut c, 5000, &fuel).await?;
    let prev = term.reversal(&c2_req, Some(3000), true);
    x.send(&prev, None, None).await?;
    x.account("Carol", carol.account_id).await?;

    x.t.h("ISSUER HANGS: the issuer process is frozen (SIGSTOP), connections stay open, nothing answers");
    issuer_ctl(&mut x.t, &o.issuer_ctl, "hang").await?;
    x.t.line("   Carol: chip + PIN $60.00 -> switch waits for its 250 ms issuer deadline, then stands in");
    let chip_c = TxnOpts::chip_pin(&carol.secret.pin);
    let (c3_req, c3_resp) = x.purchase(&mut term, &mut c, 6000, &chip_c).await?;
    x.t.line("   Carol: chip + PIN $35.00 -> second deadline miss opens the circuit breaker");
    let (c4_req, c4_resp) = x.purchase(&mut term, &mut c, 3500, &chip_c).await?;
    x.t.line("   Alice: $400.00 -> circuit open, no waiting; above the $250.00 stand-in per-transaction limit");
    x.purchase(&mut term, &mut a, 40000, &chip).await?;
    x.t.line(
        "   Alice: wrong PIN is still caught in stand-in (the HSM is up; only the issuer is down)",
    );
    x.purchase(
        &mut term,
        &mut a,
        500,
        &TxnOpts::chip_pin(if alice.secret.pin == "0000" {
            "1111"
        } else {
            "0000"
        }),
    )
    .await?;

    x.t.h("ISSUER RESUMES (SIGCONT): late requests and replayed 0120 advices meet at the issuer");
    issuer_ctl(&mut x.t, &o.issuer_ctl, "resume").await?;
    x.t.line(
        "   The frozen JVM still processes the two authorizations that timed out at the switch;",
    );
    x.t.line("   the replayed stand-in advices carry the same auth_ref, so the issuer keeps ONE hold each");
    x.t.line("   and adopts the stand-in approval code the merchant actually received.");
    let t1 = Instant::now();
    let expect = [
        (
            auth_ref(&c3_req),
            c3_resp.get_str(38).unwrap_or("").to_string(),
        ),
        (
            auth_ref(&c4_req),
            c4_resp.get_str(38).unwrap_or("").to_string(),
        ),
    ];
    wait_holds(&x.issuer, carol.account_id, &expect).await?;
    x.t.line(format!(
        "   advices reconciled {:.1} s after resume",
        t1.elapsed().as_secs_f64()
    ));
    for (r, _) in &expect {
        let adv = x
            .issuer
            .get(&format!("/api/v1/advices?authRef={r}"))
            .await?;
        for a in adv.as_array().into_iter().flatten() {
            x.t.line(format!(
                "     advice {:<40} -> {}",
                a["adviceId"].as_str().unwrap_or(""),
                a["outcome"].as_str().unwrap_or("")
            ));
        }
    }
    show_holds(&mut x, "Carol", carol.account_id).await?;

    x.t.h(
        "ISSUER CRASHES (kill -9): connection refused, immediate stand-in, advice stored on disk",
    );
    issuer_ctl(&mut x.t, &o.issuer_ctl, "kill").await?;
    let (c5_req, c5_resp) = x.purchase(&mut term, &mut c, 2000, &chip_c).await?;

    x.t.h(
        "ISSUER RESTART: switch probes health, closes the circuit and forwards the stored advice",
    );
    let t0 = Instant::now();
    issuer_ctl(&mut x.t, &o.issuer_ctl, "start").await?;
    x.t.line(format!(
        "   issuer restarted and healthy in {:.1} s",
        t0.elapsed().as_secs_f64()
    ));
    let t1 = Instant::now();
    wait_holds(
        &x.issuer,
        carol.account_id,
        &[(
            auth_ref(&c5_req),
            c5_resp.get_str(38).unwrap_or("").to_string(),
        )],
    )
    .await?;
    x.t.line(format!(
        "   stand-in advice applied {:.1} s after the issuer came back",
        t1.elapsed().as_secs_f64()
    ));
    show_holds(&mut x, "Carol", carol.account_id).await?;

    x.t.h("Clearing: acquirer presentments arrive in the daily clearing file");
    let today = Utc::now().date_naive();
    let pres = |rid: &str,
                seq: u64,
                req: &Message,
                resp: &Message,
                amount: i64,
                mcc: &str,
                merchant: &str| {
        Record::Presentment {
            record_id: rid.into(),
            arn: clearing::arn("410000", today, seq),
            pan: req.get_str(2).unwrap_or_default().into(),
            auth_code: resp.get_str(38).unwrap_or("000000").into(),
            rrn: req.get_str(37).unwrap_or_default().into(),
            terminal_id: req.get_str(41).unwrap_or_default().trim().into(),
            txn_date: today,
            amount_minor: amount,
            currency: "840".into(),
            mcc: mcc.into(),
            merchant: merchant.into(),
            seq: 1,
            count: 1,
        }
    };
    let file_id = format!("ACQ-{}", Utc::now().format("%Y%m%d%H%M%S"));
    let force = Record::Presentment {
        record_id: format!("{file_id}-4"),
        arn: clearing::arn("410000", today, 4),
        pan: alice.secret.pan.clone(),
        auth_code: "000000".into(),
        rrn: "000000000000".into(),
        terminal_id: "ECOM0001".into(),
        txn_date: today,
        amount_minor: 999,
        currency: "840".into(),
        mcc: "4899".into(),
        merchant: "STREAMING SUBSCRIPTION".into(),
        seq: 1,
        count: 1,
    };
    let alice_pres = pres(
        &format!("{file_id}-1"),
        1,
        &a1_req,
        &a1_resp,
        4250,
        "5411",
        "CORNER GROCERY",
    );
    let alice_arn = match &alice_pres {
        Record::Presentment { arn, .. } => arn.clone(),
        _ => unreachable!(),
    };
    let records = vec![
        alice_pres,
        pres(
            &format!("{file_id}-2"),
            2,
            &c1_req,
            &c1_resp,
            1500,
            "5411",
            "CORNER GROCERY",
        ),
        pres(
            &format!("{file_id}-3"),
            3,
            &c2_req,
            &c2_resp,
            3000,
            "5542",
            "FUEL STATION",
        ),
        pres(
            &format!("{file_id}-5"),
            5,
            &c3_req,
            &c3_resp,
            6000,
            "5411",
            "CORNER GROCERY",
        ),
        pres(
            &format!("{file_id}-6"),
            6,
            &c5_req,
            &c5_resp,
            2000,
            "5411",
            "CORNER GROCERY",
        ),
        force,
    ];
    let file = clearing::write_file(&file_id, today, "ACQ410000", &records);
    x.t.line("   file (PANs masked here; the file itself carries full PANs):");
    let masked: String = file
        .lines()
        .map(|l| {
            let mut f: Vec<String> = l.split('|').map(str::to_string).collect();
            if f[0] == "PRES" {
                f[3] = mask_pan(&f[3]);
            }
            f.join("|")
        })
        .collect::<Vec<_>>()
        .join("\n");
    x.t.block(&masked);
    let report = x.issuer.post_text("/api/v1/clearing/files", file).await?;
    x.t.line("   ingest result:");
    for l in report["lines"].as_array().into_iter().flatten() {
        x.t.line(format!(
            "     {:<22} {} {:>9}  {:<22} {}",
            l["recordId"].as_str().unwrap_or(""),
            l["type"].as_str().unwrap_or(""),
            money(l["amountMinor"].as_i64().unwrap_or(0)),
            l["outcome"].as_str().unwrap_or(""),
            l["authRef"].as_str().unwrap_or("(no authorization)")
        ));
    }
    x.account("Alice", alice.account_id).await?;
    x.account("Carol", carol.account_id).await?;

    x.t.h("Dispute: Alice says the $42.50 groceries were never delivered (reason 13.1)");
    let disp = x
        .issuer
        .post(
            "/api/v1/disputes",
            &json!({"presentmentRecordId": format!("{file_id}-1"), "reasonCode": "13.1",
                    "amountMinor": 4250, "note": "order never delivered"}),
        )
        .await?;
    let id = disp["id"].as_i64().unwrap_or(0);
    x.t.line(format!(
        "   opened {} state {} chargeback deadline {}",
        disp["disputeRef"].as_str().unwrap_or(""),
        disp["state"].as_str().unwrap_or(""),
        disp["chargebackDeadline"].as_str().unwrap_or("")
    ));
    x.account("Alice (provisional credit)", alice.account_id)
        .await?;
    match x
        .issuer
        .post(&format!("/api/v1/disputes/{id}/chargeback"), &json!({}))
        .await
    {
        Ok(_) => {
            x.t.line("   unexpected: chargeback accepted without evidence")
        }
        Err(e) => {
            x.t.line(format!("   chargeback without evidence refused: {e}"))
        }
    }
    x.issuer
        .post(
            &format!("/api/v1/disputes/{id}/evidence"),
            &json!({"type": "CARDHOLDER_LETTER", "description": "signed cardholder letter", "submittedBy": "cardholder"}),
        )
        .await?;
    let cb = x
        .issuer
        .post(&format!("/api/v1/disputes/{id}/chargeback"), &json!({}))
        .await?;
    x.t.line(format!(
        "   evidence added; chargeback raised -> {}",
        cb["state"].as_str().unwrap_or("")
    ));
    let outgoing = x
        .issuer
        .get_text("/api/v1/clearing/outgoing?fileId=ISS-OUT-1")
        .await?;
    x.t.line("   outgoing chargeback file to the network:");
    x.t.block(&outgoing);
    let net_file = clearing::write_file(
        &format!("NET-{}", Utc::now().format("%Y%m%d%H%M%S")),
        today,
        "NETWORK",
        &[Record::Chargeback {
            record_id: format!("NET-CB-{id}"),
            arn: alice_arn,
            dispute_ref: format!("DSP-{id}"),
            amount_minor: 4250,
            currency: "840".into(),
            reason_code: "13.1".into(),
        }],
    );
    let r = x
        .issuer
        .post_text("/api/v1/clearing/files", net_file)
        .await?;
    x.t.line(format!(
        "   network clearing confirms the chargeback: {}",
        r["lines"][0]["outcome"].as_str().unwrap_or("")
    ));
    let dv = x.issuer.get(&format!("/api/v1/disputes/{id}")).await?;
    x.t.line(format!(
        "   dispute state {} (acquirer may re-present until {})",
        dv["state"].as_str().unwrap_or(""),
        dv["representmentDeadline"].as_str().unwrap_or("")
    ));
    x.t.line("   audit trail:");
    for e in dv["events"].as_array().into_iter().flatten() {
        x.t.line(format!(
            "     {:<18} -> {:<18} by {:<10} {}",
            e["fromState"].as_str().unwrap_or("-"),
            e["toState"].as_str().unwrap_or(""),
            e["actor"].as_str().unwrap_or(""),
            e["note"].as_str().unwrap_or("")
        ));
    }
    x.account("Alice", alice.account_id).await?;

    x.t.h("Ledger check: trial balance recomputed from every posting");
    let tb = x.issuer.get("/api/v1/ledger/trial-balance").await?;
    for l in tb["accounts"].as_array().into_iter().flatten() {
        let code = l["code"].as_str().unwrap_or("");
        if !code.starts_with("CARDHOLDER") {
            x.t.line(format!(
                "     {:<24} {} {:>12}",
                code,
                l["normalSide"].as_str().unwrap_or(""),
                money(l["balanceMinor"].as_i64().unwrap_or(0))
            ));
        }
    }
    x.t.line(format!(
        "   total debits {} = total credits {}: balanced={} materialised balances match={}",
        money(tb["totalDebitsMinor"].as_i64().unwrap_or(0)),
        money(tb["totalCreditsMinor"].as_i64().unwrap_or(0)),
        tb["balanced"],
        tb["materialisedBalancesMatch"]
    ));

    x.t.h("Sign-off");
    let m = term.sign_off();
    x.send(&m, None, None).await?;

    let mut f = std::fs::File::create(&o.transcript)?;
    for l in &x.t.out {
        writeln!(f, "{l}")?;
    }
    println!("\ntranscript written to {}", o.transcript);
    Ok(())
}
