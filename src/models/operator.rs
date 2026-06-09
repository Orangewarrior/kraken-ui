use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "operators")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id_user: i32,
    pub username: String,
    #[sea_orm(unique)]
    pub email: String,
    #[sea_orm(column_name = "type")]
    pub operator_type: String,
    pub encrypted_password_hash: String,
    /// Two-factor (TOTP) status flag: 0 while disabled, 1 once an operator has
    /// confirmed an authenticator. Surfaced as the "2MFA" column in the users
    /// table.
    pub mfa_enabled: i32,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
