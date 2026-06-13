use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderValue, StatusCode, header::RETRY_AFTER},
    middleware::Next,
    response::{IntoResponse, Response},
};
use tokio::sync::Semaphore;

use crate::state::AppState;

/// How many `semaphore` calls pass between full sweeps of the dead-entry map.
/// Sweeping every call made the per-request cost O(tracked IPs); amortising it
/// keeps the steady state O(1) while still bounding the map, since a stale entry
/// is also replaced the next time its own IP returns.
const SWEEP_INTERVAL: u64 = 1024;

#[derive(Debug)]
struct LimiterState {
    semaphores: HashMap<IpAddr, Weak<Semaphore>>,
    calls_since_sweep: u64,
}

#[derive(Debug)]
pub struct IpConcurrencyLimiter {
    max_per_ip: usize,
    state: Mutex<LimiterState>,
}

impl IpConcurrencyLimiter {
    pub fn new(max_per_ip: usize) -> Self {
        Self {
            max_per_ip,
            state: Mutex::new(LimiterState {
                semaphores: HashMap::new(),
                calls_since_sweep: 0,
            }),
        }
    }

    fn semaphore(&self, ip: IpAddr) -> Option<Arc<Semaphore>> {
        let mut state = self.state.lock().ok()?;
        // Amortised cleanup: drop entries whose semaphore has no live permits only
        // once every `SWEEP_INTERVAL` calls, rather than scanning the whole map on
        // every request.
        state.calls_since_sweep += 1;
        if state.calls_since_sweep >= SWEEP_INTERVAL {
            state.calls_since_sweep = 0;
            state
                .semaphores
                .retain(|_, semaphore| semaphore.strong_count() > 0);
        }
        if let Some(semaphore) = state.semaphores.get(&ip).and_then(Weak::upgrade) {
            return Some(semaphore);
        }
        let semaphore = Arc::new(Semaphore::new(self.max_per_ip));
        state.semaphores.insert(ip, Arc::downgrade(&semaphore));
        Some(semaphore)
    }
}

/// Applies the persistent GCRA limit and a non-queuing concurrency ceiling.
///
/// `ConnectInfo` is installed by the real server. Direct router tests without
/// it skip this layer; axum-governor independently enforces its extractor.
pub async fn apply(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let Some(ConnectInfo(peer)) = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .copied()
    else {
        return next.run(request).await;
    };

    let Some(semaphore) = state.rate_limiting.ip_concurrency.semaphore(peer.ip()) else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Rate limiter temporarily unavailable",
        )
            .into_response();
    };
    let Ok(_permit) = semaphore.try_acquire_owned() else {
        return rate_limited(Duration::from_secs(1));
    };

    if let Some(limiter) = &state.rate_limiting.persistent {
        let decision = limiter.check(&peer.ip().to_string()).await;
        if !decision.allowed {
            return rate_limited(decision.retry_after);
        }
    }

    match tokio::time::timeout(state.rate_limiting.request_timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => (
            StatusCode::REQUEST_TIMEOUT,
            "Request exceeded connection_timeout_secs",
        )
            .into_response(),
    }
}

fn rate_limited(retry_after: Duration) -> Response {
    let seconds = retry_after.as_secs().max(1);
    let mut response = (StatusCode::TOO_MANY_REQUESTS, "Too many requests").into_response();
    if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
        response.headers_mut().insert(RETRY_AFTER, value);
    }
    response
}
