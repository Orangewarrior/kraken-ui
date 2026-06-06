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
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
