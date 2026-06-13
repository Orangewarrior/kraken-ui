use std::collections::HashMap;

use serde::Serialize;

/// The JSON envelope every server-side paginated table returns. It matches the
/// DataTables server-side contract (`draw`, `recordsTotal`, `recordsFiltered`,
/// `data`), so a single shape serves the operators and attacks tables alike.
#[derive(Serialize)]
pub struct PageResponse<T> {
    pub draw: u64,
    #[serde(rename = "recordsTotal")]
    pub records_total: u64,
    #[serde(rename = "recordsFiltered")]
    pub records_filtered: u64,
    pub data: Vec<T>,
}

/// Reads a `u64` query parameter, falling back to `fallback` when it is absent or
/// not a number. The value is parsed directly: `u64::from_str` only accepts ASCII
/// digits, so there is nothing for an HTML sanitiser to strip — running one here
/// would burn a full HTML parse per request on a field that can only be a number.
pub fn parse_query_u64(query: &HashMap<String, String>, key: &str, fallback: u64) -> u64 {
    query
        .get(key)
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(fallback)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::parse_query_u64;

    #[test]
    fn parses_numbers_and_falls_back_otherwise() {
        let mut query = HashMap::new();
        query.insert("start".to_owned(), " 42 ".to_owned());
        query.insert("bad".to_owned(), "12x".to_owned());
        assert_eq!(parse_query_u64(&query, "start", 0), 42);
        assert_eq!(parse_query_u64(&query, "bad", 7), 7);
        assert_eq!(parse_query_u64(&query, "missing", 9), 9);
    }
}
