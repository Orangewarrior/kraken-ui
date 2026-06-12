#![forbid(unsafe_code)]

use anyhow::Context;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use kraken_ui::{AppFactory, config::AppConfig, services::rate_limit::RateLimitConfig};
use std::{net::SocketAddr, time::Duration};
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if let Some(delay) = std::env::var("KRAKEN_UI_RESTART_DELAY_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
    {
        tokio::time::sleep(Duration::from_millis(delay.min(30_000))).await;
    }
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install the rustls aws-lc-rs crypto provider"))?;
    let config = AppConfig::load("conf/setup.yaml")
        .await
        .context("failed to load conf/setup.yaml")?;
    let rate_limit_config = RateLimitConfig::load("conf/ratelimit.yaml")
        .await
        .context("failed to load conf/ratelimit.yaml")?;
    let _log_guard = kraken_ui::app::initialize_logging(&config)
        .context("failed to initialize JSONL logging")?;
    let listen_address: SocketAddr = config
        .listen
        .parse()
        .context("invalid TLS listen address in conf/setup.yaml")?;
    let tls_config =
        RustlsConfig::from_pem_file(&config.certificate_path, &config.private_key_path)
            .await
            .context("failed to load the TLS certificate chain or private key")?;
    let server_handle = axum_server::Handle::new();
    let application = AppFactory::new(config)
        .with_rate_limit_config(rate_limit_config.clone())
        .with_server_handle(server_handle.clone())
        .build()
        .await?;

    info!(%listen_address, "starting Kraken UI with mandatory TLS");
    let acceptor = RustlsAcceptor::new(tls_config)
        .handshake_timeout(rate_limit_config.tls_handshake_timeout());
    axum_server::bind(listen_address)
        .acceptor(acceptor)
        .handle(server_handle)
        .serve(application.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .context("TLS server stopped unexpectedly")
}
