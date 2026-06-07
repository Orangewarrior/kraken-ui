pub mod database;
pub mod operator;
pub mod operator_repository;
pub mod session_store;
pub mod vulnerability;
pub mod vulnerability_repository;

use sea_orm::sea_query::LikeExpr;

use crate::security::sanitize;

/// Builds a substring `LIKE` pattern whose user-supplied part is escaped, so `%`
/// and `_` in a search term are matched literally rather than as wildcards. Pair
/// it with `Column::like(...)`, which emits the `ESCAPE '\'` clause.
pub(crate) fn like_contains(search: &str) -> LikeExpr {
    LikeExpr::new(format!("%{}%", sanitize::escape_like(search))).escape('\\')
}
