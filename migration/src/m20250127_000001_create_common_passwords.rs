use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create common_passwords table
        manager
            .create_table(
                Table::create()
                    .table(CommonPasswords::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(CommonPasswords::Password)
                            .text()
                            .not_null()
                            .primary_key(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(CommonPasswords::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum CommonPasswords {
    Table,
    Password,
}
