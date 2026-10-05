//! Persistent terminal operations used by the issuer web application.
use crate::{
    cards::{issue, CardSpec},
    client::AcquirerClient,
    demo::DemoCard,
    emvcard::{Cryptogram, EmvCard},
    issuer::Issuer,
    keys::TestKeys,
    terminal::{Entry, Terminal, TxnOpts},
};
use anyhow::Context;
use iso8583::{pad_ans, Message, Spec};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

fn private_write(path: &str, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let temporary = format!("{path}.tmp");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

pub async fn issue_card(
    keys: &TestKeys,
    issuer: &str,
    sequence: u64,
    name: &str,
    opening: i64,
    out: &str,
) -> anyhow::Result<Value> {
    anyhow::ensure!(
        (1..=999_999_999).contains(&sequence) && (0..=100_000_000_000).contains(&opening),
        "invalid issuance parameters"
    );
    if std::path::Path::new(out).exists() {
        let card: DemoCard = serde_json::from_slice(&std::fs::read(out)?)?;
        return Ok(card_summary(&card, name));
    }
    let mut spec = CardSpec::standard(name, 18, opening);
    spec.daily_txn_count_limit = 10_000;
    let draft_path = format!("{out}.issuance");
    let (secret, record) = if std::path::Path::new(&draft_path).exists() {
        serde_json::from_slice(&std::fs::read(&draft_path)?)?
    } else {
        let draft = issue(keys, sequence, &spec, &mut rand::thread_rng())?;
        private_write(&draft_path, &serde_json::to_vec(&draft)?)?;
        draft
    };
    let ids = Issuer::new(issuer).import(&[record]).await?;
    let card = DemoCard {
        secret,
        card_id: ids[0].card_id,
        account_id: ids[0].account_id,
    };
    private_write(out, &serde_json::to_vec(&card)?)?;
    Ok(card_summary(&card, name))
}
fn card_summary(card: &DemoCard, name: &str) -> Value {
    json!({"cardId":card.card_id,"accountId":card.account_id,"last4":&card.secret.pan[12..],"holderName":name,"expiry":card.secret.expiry,"status":"ACTIVE","perTxnLimitMinor":500_000})
}

#[derive(Serialize, Deserialize)]
struct SavedRequest {
    request: String,
    response_code: String,
    auth_code: String,
    arqc: Option<[u8; 8]>,
    atc: Option<[u8; 2]>,
    result: Option<Value>,
}

#[allow(clippy::too_many_arguments)] // Mirrors the terminal command and its explicit inputs.
pub async fn authorize(
    keys: &TestKeys,
    switch: &str,
    _issuer: &str,
    file: &str,
    request_file: &str,
    amount: i64,
    merchant: &str,
    mode: &str,
    verification: &str,
) -> anyhow::Result<Value> {
    anyhow::ensure!(
        (1..=100_000_000_000).contains(&amount) && merchant.is_ascii() && merchant.len() <= 40,
        "invalid authorization parameters"
    );
    let mut data: DemoCard = serde_json::from_slice(&std::fs::read(file)?)?;
    let mut card = EmvCard::personalise(data.secret.clone(), keys)?;
    let mut terminal = Terminal::new(&format!("{:08}", data.card_id % 100_000_000), keys);
    terminal.location = pad_ans(merchant, 40);
    let pin = if verification == "wrong-pin" {
        if card.secret.pin == "0000" {
            "1111"
        } else {
            "0000"
        }
    } else {
        &card.secret.pin
    };
    let mut opts = TxnOpts::chip_pin(pin);
    opts.entry = if mode == "magstripe" {
        Entry::Magstripe
    } else {
        Entry::Chip
    };
    if mode == "chip" {
        opts.pin = None;
    }
    opts.tamper_arqc = verification == "tampered";
    let mut saved: SavedRequest = if std::path::Path::new(request_file).exists() {
        serde_json::from_slice(&std::fs::read(request_file)?)?
    } else {
        let built = terminal.auth(&mut card, amount, &opts)?;
        data.secret = card.secret.clone();
        private_write(file, &serde_json::to_vec(&data)?)?;
        let saved = SavedRequest {
            request: hex::encode(built.msg.encode(&Spec::v1987_ascii())?),
            response_code: String::new(),
            auth_code: String::new(),
            arqc: built.cryptogram.as_ref().map(|c| c.arqc),
            atc: built.cryptogram.as_ref().map(|c| c.atc),
            result: None,
        };
        private_write(request_file, &serde_json::to_vec(&saved)?)?;
        saved
    };
    if let Some(result) = saved.result {
        return Ok(result);
    }
    let request = Message::decode(&Spec::v1987_ascii(), &hex::decode(&saved.request)?)?;
    // The switch refreshes new card profiles once per second.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let client = AcquirerClient::connect(switch).await?;
    client.send(&terminal.sign_on()).await?;
    let (response, latency) = client.send(&request).await?;
    let code = response.get_str(39).unwrap_or("96").to_string();
    let auth = response.get_str(38).unwrap_or("").to_string();
    let verified = response
        .get(55)
        .and_then(|b| iso8583::tlv::parse(b).ok())
        .and_then(|v| iso8583::tlv::find(&v, 0x91).map(|b| b.to_vec()))
        .zip(
            saved
                .arqc
                .zip(saved.atc)
                .map(|(arqc, atc)| Cryptogram {
                    tlvs: vec![],
                    arqc,
                    atc,
                })
                .as_ref(),
        )
        .map(|(v, c)| card.verify_arpc(c, &v))
        .unwrap_or(false);
    let result = json!({"responseCode":code,"authCode":auth,"amountMinor":amount,"merchant":merchant,"mode":mode,"verification":verification,"latencyMs":latency.as_secs_f64()*1000.,"arpcVerified":verified,"rrn":request.get_str(37),"terminalId":terminal.tid.trim(),"stan":request.get_str(11),"status":if code=="00" {"AUTHORIZED"} else {"DECLINED"}});
    saved.response_code = code;
    saved.auth_code = auth;
    saved.result = Some(result.clone());
    private_write(request_file, &serde_json::to_vec(&saved)?)?;
    Ok(result)
}

pub async fn reverse(keys: &TestKeys, switch: &str, request_file: &str) -> anyhow::Result<Value> {
    let result_file = format!("{request_file}.reversed");
    if std::path::Path::new(&result_file).exists() {
        return Ok(serde_json::from_slice(&std::fs::read(&result_file)?)?);
    }
    let saved: SavedRequest = serde_json::from_slice(&std::fs::read(request_file)?)?;
    anyhow::ensure!(
        saved.response_code == "00",
        "only an approved authorization can be reversed"
    );
    let original = Message::decode(&Spec::v1987_ascii(), &hex::decode(saved.request)?)?;
    let mut terminal = Terminal::new(original.get_str(41).unwrap_or("WEBAPP"), keys);
    let client = AcquirerClient::connect(switch).await?;
    client.send(&terminal.sign_on()).await?;
    let (r, t) = client
        .send(&terminal.reversal(&original, None, false))
        .await?;
    let code = r.get_str(39).unwrap_or("96");
    anyhow::ensure!(code == "00", "reversal declined with code {code}");
    let result = json!({"responseCode":code,"latencyMs":t.as_secs_f64()*1000.,"status":"REVERSED"});
    private_write(&result_file, &serde_json::to_vec(&result)?)?;
    Ok(result)
}

pub async fn settle(
    issuer: &str,
    card_file: &str,
    request_file: &str,
    record_id: &str,
) -> anyhow::Result<Value> {
    use crate::clearing::{self, Record};
    let result_file = format!("{request_file}.settled");
    if std::path::Path::new(&result_file).exists() {
        return Ok(serde_json::from_slice(&std::fs::read(&result_file)?)?);
    }
    let card: DemoCard = serde_json::from_slice(&std::fs::read(card_file)?)?;
    let saved: SavedRequest = serde_json::from_slice(&std::fs::read(request_file)?)?;
    anyhow::ensure!(
        saved.response_code == "00",
        "only an approved authorization can be settled"
    );
    anyhow::ensure!(
        record_id.len() <= 64 && !record_id.contains('|'),
        "invalid presentment id"
    );
    let original = Message::decode(&Spec::v1987_ascii(), &hex::decode(saved.request)?)?;
    let date = chrono::Utc::now().date_naive();
    let amount = original
        .get_str(4)
        .context("missing amount")?
        .parse::<i64>()?;
    let arn = clearing::arn(
        "410001",
        date,
        chrono::Utc::now().timestamp_millis() as u64 % 100_000_000_000,
    );
    let record = Record::Presentment {
        record_id: record_id.into(),
        arn: arn.clone(),
        pan: card.secret.pan,
        auth_code: saved.auth_code,
        rrn: original.get_str(37).unwrap_or("").into(),
        terminal_id: original.get_str(41).unwrap_or("").into(),
        txn_date: date,
        amount_minor: amount,
        currency: "840".into(),
        mcc: "5411".into(),
        merchant: original.get_str(43).unwrap_or("Merchant").trim().into(),
        seq: 1,
        count: 1,
    };
    let file = clearing::write_file(&format!("FILE-{record_id}"), date, "APPLICATION", &[record]);
    let outcome = Issuer::new(issuer)
        .post_text("/api/v1/clearing/files", file)
        .await?;
    anyhow::ensure!(
        outcome["lines"][0]["outcome"]
            .as_str()
            .is_some_and(|s| s.starts_with("MATCHED")),
        "presentment failed: {}",
        outcome["lines"][0]["outcome"]
    );
    let result = json!({"recordId":record_id,"arn":arn,"status":"SETTLED","outcome":outcome});
    private_write(&result_file, &serde_json::to_vec(&result)?)?;
    Ok(result)
}
