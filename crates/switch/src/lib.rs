//! Card authorization switch.
//!
//! Receives ISO 8583:1987 messages from acquirers over TCP, authenticates
//! the card and cardholder through the HSM (PIN, ARQC, CVV), applies card
//! and velocity rules, asks the issuer back office for an open-to-buy
//! decision, and stands in for the issuer when it is unreachable, storing
//! advices for later forwarding.

pub mod cards;
pub mod circuit;
pub mod config;
pub mod engine;
pub mod issuer;
pub mod journal;
pub mod rc;
pub mod server;
pub mod stats;
pub mod store;

use std::sync::Arc;
use std::time::Duration;

/// Wire everything together from a config (used by the binary and tests).
pub async fn build(
    cfg: config::Config,
    issuer: Arc<dyn issuer::IssuerApi>,
) -> anyhow::Result<Arc<engine::Switch>> {
    let hsm = Arc::new(
        hsm::client::HsmClient::connect(
            &cfg.hsm_addr,
            cfg.hsm_pool,
            Duration::from_millis(cfg.hsm_timeout_ms),
        )
        .await?,
    );
    let journal = journal::Journal::open(&cfg.stip_journal).await?;
    let cards = Arc::new(cards::CardCache::default());
    let sw = Arc::new(engine::Switch::new(cfg, hsm, issuer, cards, journal)?);
    match sw.refresh_cards().await {
        Ok(n) => tracing::info!(cards = n, "card snapshot loaded from issuer"),
        Err(e) => match sw.cards.load(&sw.cfg.card_snapshot_file) {
            Ok(n) => {
                tracing::warn!(error = %e, cards = n, "issuer unreachable; using persisted card snapshot")
            }
            Err(_) => tracing::error!(error = %e, "no card data available"),
        },
    }
    Ok(sw)
}
