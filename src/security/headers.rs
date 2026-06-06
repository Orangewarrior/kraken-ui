use std::path::Path;

use anyhow::{Context, bail};
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use memchr::memchr;
use tokio::fs;

pub async fn load(path: impl AsRef<Path>) -> anyhow::Result<HeaderMap> {
    let path = path.as_ref();
    let content = fs::read_to_string(path)
        .await
        .with_context(|| format!("unable to read security headers from {}", path.display()))?;
    parse(&content)
}

pub fn parse(content: &str) -> anyhow::Result<HeaderMap> {
    let mut headers = HeaderMap::new();

    for (line_index, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let separator = memchr(b':', line.as_bytes())
            .with_context(|| format!("missing ':' on security header line {}", line_index + 1))?;
        let name = line[..separator].trim();
        let value = line[separator + 1..].trim();
        if name.is_empty() || value.is_empty() {
            bail!(
                "empty name or value on security header line {}",
                line_index + 1
            );
        }

        let header_name = HeaderName::from_bytes(name.as_bytes())
            .with_context(|| format!("invalid header name on line {}", line_index + 1))?;
        let header_value = HeaderValue::from_str(value)
            .with_context(|| format!("invalid header value on line {}", line_index + 1))?;
        headers.insert(header_name, header_value);
    }

    if headers.is_empty() {
        bail!("security header file cannot be empty");
    }
    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn parses_header_values_containing_colons() {
        let headers = parse("Example: value:with:colons");
        assert!(headers.is_ok());
    }
}
