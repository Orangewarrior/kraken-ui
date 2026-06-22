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

/// Console roles persisted in the `operators.type` column.
///
/// The database stores these as lowercase strings for compatibility with the
/// existing schema; the enum keeps authorization decisions out of scattered
/// string comparisons.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperatorRole {
    Admin,
    Operator,
    Auditor,
}

impl OperatorRole {
    pub const ALL: [Self; 3] = [Self::Admin, Self::Operator, Self::Auditor];

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "admin" => Some(Self::Admin),
            "operator" => Some(Self::Operator),
            "auditor" => Some(Self::Auditor),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Operator => "operator",
            Self::Auditor => "auditor",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Admin => "Admin",
            Self::Operator => "Operator",
            Self::Auditor => "Auditor",
        }
    }

    pub fn can_use_console(self) -> bool {
        true
    }

    pub fn can_administer(self) -> bool {
        self == Self::Admin
    }

    pub fn can_manage_rules(self) -> bool {
        matches!(self, Self::Admin | Self::Operator)
    }
}

impl Model {
    pub fn role(&self) -> Option<OperatorRole> {
        OperatorRole::parse(&self.operator_type)
    }
}
