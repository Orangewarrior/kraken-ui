pub mod database;
pub mod operator;
pub mod operator_mfa_recovery_code;
pub mod operator_mfa_repository;
pub mod operator_mfa_totp;
pub mod operator_repository;
pub mod session_store;
pub mod vulnerability;
pub mod vulnerability_repository;

use sea_orm::sea_query::LikeExpr;

use crate::security::sanitize;

/// The canonical timestamp text written to every `created_at` / `updated_at` /
/// `confirmed_at` / `used_at` column in this database: UTC, formatted as
/// `YYYY-MM-DD HH:MM:SS`. A fixed-width, second-precision form keeps the DataTables
/// date columns compact and sorts correctly as text.
pub fn current_timestamp() -> String {
    use time::macros::format_description;
    let format = format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
    time::OffsetDateTime::now_utc()
        .format(&format)
        .unwrap_or_default()
}

/// Builds a substring `LIKE` pattern whose user-supplied part is escaped, so `%`
/// and `_` in a search term are matched literally rather than as wildcards. Pair
/// it with `Column::like(...)`, which emits the `ESCAPE '\'` clause.
pub(crate) fn like_contains(search: &str) -> LikeExpr {
    LikeExpr::new(format!("%{}%", sanitize::escape_like(search))).escape('\\')
}

#[cfg(test)]
mod tests {
    use super::current_timestamp;

    #[test]
    fn timestamp_uses_fixed_width_sql_format() {
        let timestamp = current_timestamp();
        // Exactly "YYYY-MM-DD HH:MM:SS": 19 characters, no timezone suffix or
        // sub-second precision, so DataTables date columns stay compact.
        assert_eq!(timestamp.len(), 19, "got: {timestamp}");
        let bytes = timestamp.as_bytes();
        assert_eq!(bytes[4], b'-');
        assert_eq!(bytes[7], b'-');
        assert_eq!(bytes[10], b' ');
        assert_eq!(bytes[13], b':');
        assert_eq!(bytes[16], b':');
        assert!(
            timestamp
                .chars()
                .all(|character| character.is_ascii_digit() || matches!(character, '-' | ' ' | ':'))
        );
    }
}
