use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(unique)]
    pub username: String,
    pub password_hash: String,
    pub created_at: i64,
    
    // Admin role flags
    pub is_owner: bool,
    pub is_system_admin: bool,
    pub is_role_admin: bool,
    
    // Application roles (JSON array of strings)
    pub app_roles: Option<String>,
    
    // Password management
    pub password_change_required: bool,
    
    // Last modification timestamp
    pub updated_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
