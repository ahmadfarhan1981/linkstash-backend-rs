use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "hibp_cache")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub hash_prefix: String,
    pub response_data: String,
    pub fetched_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
