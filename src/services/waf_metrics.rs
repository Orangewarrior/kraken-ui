use std::{collections::HashMap, path::Path, time::Duration};

use anyhow::{Context, bail};
use reqwest::{Certificate, Client};
use serde::Serialize;

#[derive(Clone)]
pub struct WafMetricsService {
    client: Client,
    endpoint: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct WafMetricsSnapshot {
    pub requests_inspected: f64,
    pub requests_blocked: f64,
    pub rate_limit_hits: f64,
    pub redis_rate_limit_failopen: f64,
    pub redis_rate_limit_failclosed: f64,
    pub traceparent_forwarded: f64,
    pub traceparent_generated: f64,
    pub request_duration_count: f64,
    pub request_duration_sum: f64,
    pub module_blocks: Vec<ModuleMetric>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ModuleMetric {
    pub engine: String,
    pub module: String,
    pub value: f64,
}

impl WafMetricsService {
    pub fn without_custom_ca(endpoint: &str) -> anyhow::Result<Self> {
        let client = Client::builder()
            .https_only(true)
            .timeout(Duration::from_secs(5))
            .build()
            .context("failed to build WAF metrics HTTPS client")?;
        Ok(Self {
            client,
            endpoint: endpoint.trim_end_matches('/').to_owned(),
        })
    }

    pub async fn new(endpoint: &str, certificate_path: &Path) -> anyhow::Result<Self> {
        let certificate_bytes = tokio::fs::read(certificate_path)
            .await
            .with_context(|| format!("failed to read WAF CA {}", certificate_path.display()))?;
        let certificate =
            Certificate::from_pem(&certificate_bytes).context("failed to parse WAF CA PEM")?;
        let client = Client::builder()
            .https_only(true)
            .add_root_certificate(certificate)
            .timeout(Duration::from_secs(5))
            .build()
            .context("failed to build WAF metrics HTTPS client")?;
        Ok(Self {
            client,
            endpoint: endpoint.trim_end_matches('/').to_owned(),
        })
    }

    pub async fn fetch(&self) -> anyhow::Result<WafMetricsSnapshot> {
        let primary = format!("{}/metrics", self.endpoint);
        match self.fetch_url(&primary).await {
            Ok(snapshot) => Ok(snapshot),
            Err(primary_error) => {
                let compatibility = format!("{}/__kwaf/metrics", self.endpoint);
                self.fetch_url(&compatibility).await.with_context(|| {
                    format!("WAF metrics endpoints failed; primary error: {primary_error}")
                })
            }
        }
    }

    async fn fetch_url(&self, url: &str) -> anyhow::Result<WafMetricsSnapshot> {
        let response = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "text/plain")
            .send()
            .await
            .context("failed to request WAF metrics")?;
        if !response.status().is_success() {
            bail!("WAF metrics returned HTTP {}", response.status());
        }
        let body = response
            .text()
            .await
            .context("failed to read WAF metrics response")?;
        Ok(parse_prometheus(&body))
    }
}

fn parse_prometheus(input: &str) -> WafMetricsSnapshot {
    let mut scalar = HashMap::<&str, f64>::new();
    let mut modules = Vec::new();
    for raw_line in input.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name_and_labels, value)) = line.rsplit_once(char::is_whitespace) else {
            continue;
        };
        let Ok(value) = value.trim().parse::<f64>() else {
            continue;
        };
        if let Some(labels) = name_and_labels
            .strip_prefix("krakenwaf_module_blocks_total{")
            .and_then(|value| value.strip_suffix('}'))
        {
            let labels = parse_labels(labels);
            if let (Some(engine), Some(module)) = (labels.get("engine"), labels.get("module")) {
                modules.push(ModuleMetric {
                    engine: engine.clone(),
                    module: module.clone(),
                    value,
                });
            }
        } else {
            scalar.insert(name_and_labels, value);
        }
    }
    modules.sort_by(|left, right| {
        right
            .value
            .total_cmp(&left.value)
            .then(left.module.cmp(&right.module))
    });
    WafMetricsSnapshot {
        requests_inspected: metric(&scalar, "krakenwaf_requests_inspected_total"),
        requests_blocked: metric(&scalar, "krakenwaf_requests_blocked_total"),
        rate_limit_hits: metric(&scalar, "krakenwaf_rate_limit_hits_total"),
        redis_rate_limit_failopen: metric(&scalar, "krakenwaf_redis_rate_limit_failopen_total"),
        redis_rate_limit_failclosed: metric(&scalar, "krakenwaf_redis_rate_limit_failclosed_total"),
        traceparent_forwarded: metric(&scalar, "krakenwaf_traceparent_forwarded_total"),
        traceparent_generated: metric(&scalar, "krakenwaf_traceparent_generated_total"),
        request_duration_count: metric(&scalar, "krakenwaf_request_duration_milliseconds_count"),
        request_duration_sum: metric(&scalar, "krakenwaf_request_duration_milliseconds_sum"),
        module_blocks: modules,
    }
}

fn parse_labels(input: &str) -> HashMap<&str, String> {
    input
        .split(',')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            Some((key.trim(), value.trim().trim_matches('"').to_owned()))
        })
        .collect()
}

fn metric(values: &HashMap<&str, f64>, name: &str) -> f64 {
    values.get(name).copied().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::parse_prometheus;

    #[test]
    fn parses_scalar_and_module_metrics() {
        let snapshot = parse_prometheus(
            "krakenwaf_requests_inspected_total 12\n\
             krakenwaf_request_duration_milliseconds_count 4\n\
             krakenwaf_request_duration_milliseconds_sum 20\n\
             krakenwaf_module_blocks_total{engine=\"cmc\",module=\"ssti_detect\"} 3\n",
        );
        assert_eq!(snapshot.requests_inspected, 12.0);
        assert_eq!(snapshot.request_duration_count, 4.0);
        assert_eq!(snapshot.module_blocks[0].module, "ssti_detect");
    }
}
