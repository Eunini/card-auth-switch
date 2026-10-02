use clap::Parser;
use std::sync::Arc;
use std::time::Duration;
use switch::config::Config;
use switch::issuer::HttpIssuer;

#[derive(Parser)]
#[command(about = "ISO 8583 card authorization switch")]
struct Cli {
    #[arg(long, default_value = "config/switch.toml")]
    config: String,
    /// Write latency/response-code statistics as JSON here on shutdown.
    #[arg(long)]
    stats_out: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    let cfg = Config::load(&cli.config)?;
    let issuer = Arc::new(HttpIssuer::new(
        &cfg.issuer_url,
        Duration::from_millis(cfg.issuer_timeout_ms),
    )?);
    let listen = cfg.listen.clone();
    let sw = switch::build(cfg, issuer).await?;
    sw.spawn_background();
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    tracing::info!(%listen, "switch listening");

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        r = switch::server::serve(listener, sw.clone()) => r?,
        _ = tokio::signal::ctrl_c() => {},
        _ = term.recv() => {},
    }
    let summary = sw.stats.summary();
    tracing::info!(stats = %summary, saf_pending = sw.journal.pending_len(), "shutting down");
    if let Some(p) = cli.stats_out {
        std::fs::write(p, serde_json::to_vec_pretty(&summary)?)?;
    }
    Ok(())
}
