use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Router,
    extract::{ConnectInfo, State},
    http::StatusCode,
    routing::get,
};
use kraken_ui::services::rate_limit::{
    BackendKind, PersistentRateLimiter, RateLimitConfig, RedisConfig, SqliteConfig,
};

#[tokio::test]
async fn repeated_reqwest_requests_are_limited_by_sqlite_gcra() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let config = RateLimitConfig {
        enabled: true,
        requests_per_second: 1,
        burst_size: 3,
        max_coroutines_per_ip: 8,
        tls_handshake_timeout_secs: 2,
        connection_timeout_secs: 2,
        max_tracked_ips: 100,
        backend: BackendKind::Sqlite,
        fail_open: false,
        sqlite: SqliteConfig {
            path: directory.path().join("rate-limit.sqlite"),
            busy_timeout_ms: 500,
            cleanup_interval_requests: 10,
        },
        redis: RedisConfig {
            host: "redis.example.invalid".to_owned(),
            port: 6379,
            database: 0,
            tls: true,
            key_prefix: "kraken-ui:test:".to_owned(),
            connect_timeout_secs: 1,
            response_timeout_secs: 1,
            retries: 0,
        },
    };
    let limiter = Arc::new(
        PersistentRateLimiter::from_config(&config)
            .await
            .expect("SQLite limiter"),
    );
    let app = Router::new()
        .route(
            "/limited",
            get(
                |State(limiter): State<Arc<PersistentRateLimiter>>,
                 ConnectInfo(peer): ConnectInfo<SocketAddr>| async move {
                    let decision = limiter.check(&peer.ip().to_string()).await;
                    if decision.allowed {
                        StatusCode::OK
                    } else {
                        StatusCode::TOO_MANY_REQUESTS
                    }
                },
            ),
        )
        .with_state(limiter)
        .layer(config.governor_layer().expect("governor layer"));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener");
    let address = listener.local_addr().expect("listener address");
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("serve test app");
    });

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("reqwest client");
    let mut statuses = Vec::new();
    for _ in 0..12 {
        statuses.push(
            client
                .get(format!("http://{address}/limited"))
                .send()
                .await
                .expect("HTTP request")
                .status(),
        );
    }

    server.abort();
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::OK)
            .count(),
        3
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::TOO_MANY_REQUESTS)
            .count(),
        9
    );
}
