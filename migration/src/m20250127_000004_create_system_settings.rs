use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create system_settings table
        manager
            .create_table(
                Table::create()
                    .table(SystemSettings::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SystemSettings::Key)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(SystemSettings::Value)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SystemSettings::Description)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(SystemSettings::Category)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(SystemSettings::CreatedAt)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SystemSettings::UpdatedAt)
                            .big_integer()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Create index on category for efficient filtering
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_system_settings_category")
                    .table(SystemSettings::Table)
                    .col(SystemSettings::Category)
                    .to_owned(),
            )
            .await?;

        // Insert sample data for rate limiting and audit retention settings
        let now = 0i64; // Initial timestamp, will be updated when settings are modified
        
        // Rate limiting settings
        manager
            .exec_stmt(
                Query::insert()
                    .into_table(SystemSettings::Table)
                    .columns([
                        SystemSettings::Key,
                        SystemSettings::Value,
                        SystemSettings::Description,
                        SystemSettings::Category,
                        SystemSettings::CreatedAt,
                        SystemSettings::UpdatedAt,
                    ])
                    .values_panic([
                        "rate_limiting_enabled".into(),
                        "true".into(),
                        "Enable or disable rate limiting for API endpoints".into(),
                        "security".into(),
                        now.into(),
                        now.into(),
                    ])
                    .to_owned(),
            )
            .await?;

        // Audit retention settings
        manager
            .exec_stmt(
                Query::insert()
                    .into_table(SystemSettings::Table)
                    .columns([
                        SystemSettings::Key,
                        SystemSettings::Value,
                        SystemSettings::Description,
                        SystemSettings::Category,
                        SystemSettings::CreatedAt,
                        SystemSettings::UpdatedAt,
                    ])
                    .values_panic([
                        "audit_retention_days".into(),
                        "90".into(),
                        "Number of days to retain audit log entries".into(),
                        "audit".into(),
                        now.into(),
                        now.into(),
                    ])
                    .to_owned(),
            )
            .await?;

        // JWT expiration settings (for future use when migrating from hardcoded values)
        manager
            .exec_stmt(
                Query::insert()
                    .into_table(SystemSettings::Table)
                    .columns([
                        SystemSettings::Key,
                        SystemSettings::Value,
                        SystemSettings::Description,
                        SystemSettings::Category,
                        SystemSettings::CreatedAt,
                        SystemSettings::UpdatedAt,
                    ])
                    .values_panic([
                        "jwt_expiration_minutes".into(),
                        "15".into(),
                        "JWT token expiration time in minutes".into(),
                        "authentication".into(),
                        now.into(),
                        now.into(),
                    ])
                    .to_owned(),
            )
            .await?;

        // Refresh token expiration settings
        manager
            .exec_stmt(
                Query::insert()
                    .into_table(SystemSettings::Table)
                    .columns([
                        SystemSettings::Key,
                        SystemSettings::Value,
                        SystemSettings::Description,
                        SystemSettings::Category,
                        SystemSettings::CreatedAt,
                        SystemSettings::UpdatedAt,
                    ])
                    .values_panic([
                        "refresh_token_expiration_days".into(),
                        "7".into(),
                        "Refresh token expiration time in days".into(),
                        "authentication".into(),
                        now.into(),
                        now.into(),
                    ])
                    .to_owned(),
            )
            .await

    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(SystemSettings::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum SystemSettings {
    Table,
    Key,
    Value,
    Description,
    Category,
    CreatedAt,
    UpdatedAt,
}