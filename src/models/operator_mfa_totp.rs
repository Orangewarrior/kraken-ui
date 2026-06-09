use sea_orm::entity::prelude::*;

/// The TOTP shared secret for an operator. There is at most one row per account
/// (`id_user` is unique). `encrypted_secret` holds the base32 secret sealed by
/// the password-crypto envelope; `confirmed` is 1 only after the operator proves
/// possession of the authenticator by entering a valid code.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "operator_mfa_totp")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id_totp: i32,
    #[sea_orm(unique)]
    pub id_user: i32,
    pub encrypted_secret: String,
    pub confirmed: i32,
    pub created_at: String,
    pub confirmed_at: Option<String>,
    /// The highest TOTP time-step (`unix_time / period`) that has already
    /// authenticated this account. A presented code is accepted only when its
    /// step is strictly greater, so a code cannot be replayed inside its skew
    /// window (RFC 6238 §5.2). `0` until the first successful verification.
    pub last_used_step: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
