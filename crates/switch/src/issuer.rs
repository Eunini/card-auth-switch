//! Client for the issuer back office's internal API (HTTP/JSON).

use crate::cards::CardProfile;
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthRequest {
    /// Deterministic reference built from the reversal matching key
    /// (terminal, date, STAN, RRN); the issuer uses it for idempotency.
    pub auth_ref: String,
    pub card_id: i64,
    pub account_id: i64,
    pub amount_minor: i64,
    pub currency: String,
    /// PURCHASE or CASH
    pub txn_type: String,
    pub mcc: String,
    pub stan: String,
    pub rrn: String,
    pub terminal_id: String,
    pub merchant_id: String,
    pub merchant_name: String,
    pub entry_mode: String,
    pub transmitted_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthResponse {
    pub approved: bool,
    pub response_code: String,
    pub auth_code: Option<String>,
    pub available_minor: Option<i64>,
}

/// Advice of a decision already taken (switch stand-in or acquirer). The
/// issuer must record it, and for approvals place the hold even if that
/// overdraws the account.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AdviceRequest {
    pub advice_id: String,
    /// SWITCH_STIP or ACQUIRER
    pub source: String,
    pub response_code: String,
    pub auth_code: Option<String>,
    pub auth: AuthRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReversalRequest {
    pub reversal_ref: String,
    pub auth_ref: String,
    /// Amount that remains authorised after a partial reversal; `None`
    /// for a full reversal.
    pub replacement_amount_minor: Option<i64>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReversalResponse {
    /// REVERSED, PARTIALLY_REVERSED, ALREADY_REVERSED, NOT_FOUND, NOTHING_TO_REVERSE
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AckResponse {
    pub status: String,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum IssuerError {
    #[error("issuer timeout")]
    Timeout,
    #[error("issuer unavailable: {0}")]
    Unavailable(String),
    #[error("issuer rejected request: {0}")]
    Rejected(String),
}

impl IssuerError {
    /// Whether this failure means "issuer down" (stand in) rather than a
    /// definitive answer.
    pub fn is_outage(&self) -> bool {
        !matches!(self, IssuerError::Rejected(_))
    }
}

pub trait IssuerApi: Send + Sync {
    fn authorize(&self, r: AuthRequest) -> BoxFuture<'_, Result<AuthResponse, IssuerError>>;
    fn advice(&self, r: AdviceRequest) -> BoxFuture<'_, Result<AckResponse, IssuerError>>;
    fn reverse(&self, r: ReversalRequest) -> BoxFuture<'_, Result<ReversalResponse, IssuerError>>;
    fn card_snapshot(&self) -> BoxFuture<'_, Result<Vec<CardProfile>, IssuerError>>;
    fn health(&self) -> BoxFuture<'_, Result<(), IssuerError>>;
}

pub struct HttpIssuer {
    base: String,
    http: reqwest::Client,
    deadline: Duration,
}

impl HttpIssuer {
    pub fn new(base: &str, deadline: Duration) -> anyhow::Result<Self> {
        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            http: reqwest::Client::builder()
                .tcp_nodelay(true)
                .pool_max_idle_per_host(256)
                .pool_idle_timeout(Duration::from_secs(60))
                .connect_timeout(Duration::from_millis(500))
                .build()?,
            deadline,
        })
    }

    async fn post<B: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
        deadline: Duration,
    ) -> Result<R, IssuerError> {
        let resp = self
            .http
            .post(format!("{}{path}", self.base))
            .json(body)
            .timeout(deadline)
            .send()
            .await
            .map_err(map_err)?;
        decode(resp).await
    }
}

fn map_err(e: reqwest::Error) -> IssuerError {
    if e.is_timeout() {
        IssuerError::Timeout
    } else {
        IssuerError::Unavailable(e.to_string())
    }
}

async fn decode<R: for<'de> Deserialize<'de>>(resp: reqwest::Response) -> Result<R, IssuerError> {
    let status = resp.status();
    if status.is_server_error() {
        return Err(IssuerError::Unavailable(format!("HTTP {status}")));
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(IssuerError::Rejected(format!("HTTP {status}: {body}")));
    }
    resp.json::<R>().await.map_err(map_err)
}

impl IssuerApi for HttpIssuer {
    fn authorize(&self, r: AuthRequest) -> BoxFuture<'_, Result<AuthResponse, IssuerError>> {
        Box::pin(async move {
            self.post("/internal/v1/authorizations", &r, self.deadline)
                .await
        })
    }

    fn advice(&self, r: AdviceRequest) -> BoxFuture<'_, Result<AckResponse, IssuerError>> {
        // Advices are not on the cardholder's critical path: allow longer.
        Box::pin(async move {
            self.post("/internal/v1/advices", &r, Duration::from_secs(5))
                .await
        })
    }

    fn reverse(&self, r: ReversalRequest) -> BoxFuture<'_, Result<ReversalResponse, IssuerError>> {
        Box::pin(async move {
            self.post("/internal/v1/reversals", &r, self.deadline * 4)
                .await
        })
    }

    fn card_snapshot(&self) -> BoxFuture<'_, Result<Vec<CardProfile>, IssuerError>> {
        Box::pin(async move {
            let resp = self
                .http
                .get(format!("{}/internal/v1/cards/snapshot", self.base))
                .timeout(Duration::from_secs(10))
                .send()
                .await
                .map_err(map_err)?;
            decode(resp).await
        })
    }

    fn health(&self) -> BoxFuture<'_, Result<(), IssuerError>> {
        Box::pin(async move {
            let resp = self
                .http
                .get(format!("{}/internal/v1/health", self.base))
                .timeout(Duration::from_millis(500))
                .send()
                .await
                .map_err(map_err)?;
            if resp.status().is_success() {
                Ok(())
            } else {
                Err(IssuerError::Unavailable(format!("HTTP {}", resp.status())))
            }
        })
    }
}
