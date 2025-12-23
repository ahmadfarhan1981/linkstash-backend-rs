use sea_orm::entity::prelude::*;
use crate::types::internal::context::RequestContext;

/// SeaORM entity for audit_events table
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "audit_events")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub timestamp: String,
    pub event_type: String,
    pub context: RequestContext,
    pub user_id: String,
    pub ip_address: Option<String>,
    pub jwt_id: Option<String>,
    pub data: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
