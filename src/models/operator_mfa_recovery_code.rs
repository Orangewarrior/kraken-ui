use sea_orm::entity::prelude::*;

/// A single-use recovery code for an operator. The code is sealed at rest in the
/// password-crypto envelope and burned (`used` = 1) the first time it
/// authenticates a login, so a captured code cannot be replayed.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "operator_mfa_recovery_codes")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id_code: i32,
    pub id_user: i32,
    pub encrypted_code: String,
    pub used: i32,
    pub created_at: String,
    pub used_at: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
