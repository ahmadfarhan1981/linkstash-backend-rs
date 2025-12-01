use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create hibp_cache table
        manager
            .create_table(
                Table::create()
                    .table(HibpCache::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(HibpCache::HashPrefix)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(HibpCache::ResponseData)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(HibpCache::FetchedAt)
                            .big_integer()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(HibpCache::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum HibpCache {
    Table,
    HashPrefix,
    ResponseData,
    FetchedAt,
}
