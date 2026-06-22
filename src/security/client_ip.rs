use std::net::IpAddr;

use axum::http::HeaderMap;

/// Returns the client IP used for throttling and audit.
///
/// By default the direct TCP peer wins. Forwarding headers are considered only
/// when that peer is in `trusted_proxy_ips`; this keeps spoofed client-supplied
/// headers inert in direct deployments.
pub fn effective_client_ip(
    peer_ip: IpAddr,
    headers: &HeaderMap,
    trusted_proxy_ips: &[IpAddr],
) -> IpAddr {
    if !trusted_proxy_ips.contains(&peer_ip) {
        return peer_ip;
    }
    forwarded_for(headers)
        .or_else(|| x_forwarded_for(headers))
        .or_else(|| x_real_ip(headers))
        .unwrap_or(peer_ip)
}

fn forwarded_for(headers: &HeaderMap) -> Option<IpAddr> {
    let value = headers.get("forwarded")?.to_str().ok()?;
    for part in value.split(';') {
        let (name, value) = part.split_once('=')?;
        if name.trim().eq_ignore_ascii_case("for") {
            return parse_forwarded_ip(value.trim());
        }
    }
    None
}

fn x_forwarded_for(headers: &HeaderMap) -> Option<IpAddr> {
    let value = headers.get("x-forwarded-for")?.to_str().ok()?;
    value
        .split(',')
        .find_map(|part| parse_forwarded_ip(part.trim()))
}

fn x_real_ip(headers: &HeaderMap) -> Option<IpAddr> {
    let value = headers.get("x-real-ip")?.to_str().ok()?;
    parse_forwarded_ip(value.trim())
}

fn parse_forwarded_ip(value: &str) -> Option<IpAddr> {
    let value = value.trim_matches('"');
    let value = value
        .strip_prefix('[')
        .and_then(|rest| {
            let (address, _port) = rest.split_once(']')?;
            Some(address)
        })
        .unwrap_or(value);
    let value = value
        .rsplit_once(':')
        .and_then(|(address, port)| port.parse::<u16>().ok().map(|_| address))
        .unwrap_or(value);
    value.parse().ok()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use axum::http::{HeaderMap, HeaderValue};

    use super::effective_client_ip;

    #[test]
    fn ignores_forwarded_headers_from_untrusted_peers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.10"));

        assert_eq!(
            effective_client_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), &headers, &[]),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))
        );
    }

    #[test]
    fn accepts_first_forwarded_ip_from_trusted_peer() {
        let proxy = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.10, 198.51.100.2"),
        );

        assert_eq!(
            effective_client_ip(proxy, &headers, &[proxy]),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))
        );
    }

    #[test]
    fn parses_forwarded_header_when_trusted() {
        let proxy = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let mut headers = HeaderMap::new();
        headers.insert(
            "forwarded",
            HeaderValue::from_static("for=\"203.0.113.20\";proto=https"),
        );

        assert_eq!(
            effective_client_ip(proxy, &headers, &[proxy]),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20))
        );
    }
}
