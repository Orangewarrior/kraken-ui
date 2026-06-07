use std::collections::HashMap;

use serde::Serialize;

use crate::security::sanitize;

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

/// Reads a `u64` query parameter, sanitising the raw value and falling back to
/// `fallback` when it is absent or not a number.
pub fn parse_query_u64(query: &HashMap<String, String>, key: &str, fallback: u64) -> u64 {
    query
        .get(key)
        .map(|value| sanitize::plain_text(value))
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(fallback)
}
