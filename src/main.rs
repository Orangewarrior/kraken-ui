#![forbid(unsafe_code)]

use anyhow::Context;
use axum_server::tls_rustls::RustlsConfig;
use kraken_ui::{AppFactory, config::AppConfig};
use std::net::SocketAddr;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install the rustls aws-lc-rs crypto provider"))?;
    let config = AppConfig::load("conf/setup.yaml")
        .await
        .context("failed to load conf/setup.yaml")?;
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
    let application = AppFactory::new(config).build().await?;

    info!(%listen_address, "starting Kraken UI with mandatory TLS");
    axum_server::bind_rustls(listen_address, tls_config)
        .serve(application.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .context("TLS server stopped unexpectedly")
}
