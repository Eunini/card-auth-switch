//! Small client for the issuer back office admin API (used by the demo
//! and to import generated cards).

use crate::cards::IssuerCardRecord;
use serde::Deserialize;
use serde_json::Value;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    pub pan_ref: String,
    pub card_id: i64,
    pub account_id: i64,
    pub created: bool,
}

pub struct Issuer {
    pub base: String,
    http: reqwest::Client,
}

impl Issuer {
    pub fn new(base: &str) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .expect("http client"),
        }
    }

    async fn check(resp: reqwest::Response) -> anyhow::Result<Value> {
        let status = resp.status();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            anyhow::bail!("issuer returned {status}: {body}");
        }
        Ok(body)
    }

    pub async fn healthy(&self) -> bool {
        matches!(
            self.http
                .get(format!("{}/internal/v1/health", self.base))
                .timeout(Duration::from_millis(500))
                .send()
                .await,
            Ok(r) if r.status().is_success()
        )
    }

    pub async fn import(&self, cards: &[IssuerCardRecord]) -> anyhow::Result<Vec<ImportResult>> {
        let mut out = Vec::new();
        for chunk in cards.chunks(500) {
            let r = self
                .http
                .post(format!("{}/api/v1/cards/import", self.base))
                .json(chunk)
                .send()
                .await?;
            out.extend(serde_json::from_value::<Vec<ImportResult>>(
                Self::check(r).await?,
            )?);
        }
        Ok(out)
    }

    pub async fn get(&self, path: &str) -> anyhow::Result<Value> {
        Self::check(self.http.get(format!("{}{path}", self.base)).send().await?).await
    }

    pub async fn get_text(&self, path: &str) -> anyhow::Result<String> {
        Ok(self
            .http
            .get(format!("{}{path}", self.base))
            .send()
            .await?
            .text()
            .await?)
    }

    pub async fn post(&self, path: &str, body: &Value) -> anyhow::Result<Value> {
        Self::check(
            self.http
                .post(format!("{}{path}", self.base))
                .json(body)
                .send()
                .await?,
        )
        .await
    }

    pub async fn post_text(&self, path: &str, body: String) -> anyhow::Result<Value> {
        Self::check(
            self.http
                .post(format!("{}{path}", self.base))
                .header("content-type", "text/plain")
                .body(body)
                .send()
                .await?,
        )
        .await
    }
}
