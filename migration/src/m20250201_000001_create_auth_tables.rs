use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create users table
        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Users::Id).string().not_null().primary_key())
                    .col(ColumnDef::new(Users::Username).string().not_null().unique_key())
                    .col(ColumnDef::new(Users::PasswordHash).string().null())
                    .col(ColumnDef::new(Users::CreatedAt).big_integer().not_null())
                    .col(ColumnDef::new(Users::IsOwner).boolean().not_null().default(false))
                    .col(ColumnDef::new(Users::IsSystemAdmin).boolean().not_null().default(false))
                    .col(ColumnDef::new(Users::IsRoleAdmin).boolean().not_null().default(false))
                    .col(ColumnDef::new(Users::AppRoles).string())
                    .col(ColumnDef::new(Users::PasswordChangeRequired).boolean().not_null().default(false))
                    .col(ColumnDef::new(Users::UpdatedAt).big_integer().not_null())
                    .to_owned(),
            )
            .await?;

        // Create refresh_tokens table
        manager
            .create_table(
                Table::create()
                    .table(RefreshTokens::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(RefreshTokens::TokenHash).string().not_null().primary_key())
                    .col(ColumnDef::new(RefreshTokens::UserId).string().not_null())
                    .col(ColumnDef::new(RefreshTokens::ExpiresAt).big_integer().not_null())
                    .col(ColumnDef::new(RefreshTokens::CreatedAt).big_integer().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_refresh_tokens_user_id")
                            .from(RefreshTokens::Table, RefreshTokens::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                    )
                    .to_owned(),
            )
            .await?;

        // Create indexes for refresh_tokens table
        manager
            .create_index(
                Index::create()
                    .name("idx_refresh_tokens_user_id")
                    .table(RefreshTokens::Table)
                    .col(RefreshTokens::UserId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_refresh_tokens_expires_at")
                    .table(RefreshTokens::Table)
                    .col(RefreshTokens::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        // Create common_passwords table
        manager
            .create_table(
                Table::create()
                    .table(CommonPasswords::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(CommonPasswords::Password).string().not_null().primary_key())
                    .to_owned(),
            )
            .await?;

        // Create hibp_cache table
        manager
            .create_table(
                Table::create()
                    .table(HibpCache::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(HibpCache::HashPrefix).string().not_null().primary_key())
                    .col(ColumnDef::new(HibpCache::ResponseData).string().not_null())
                    .col(ColumnDef::new(HibpCache::FetchedAt).big_integer().not_null())
                    .to_owned(),
            )
            .await?;

        // Create system_config table
        manager
            .create_table(
                Table::create()
                    .table(SystemConfig::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(SystemConfig::Id).integer().not_null().primary_key())
                    .col(ColumnDef::new(SystemConfig::OwnerActive).boolean().not_null().default(false))
                    .col(ColumnDef::new(SystemConfig::UpdatedAt).big_integer().not_null())
                    .to_owned(),
            )
            .await?;

        // Create system_settings table
        manager
            .create_table(
                Table::create()
                    .table(SystemSettings::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(SystemSettings::Key).string().not_null().primary_key())
                    .col(ColumnDef::new(SystemSettings::Value).string().not_null())
                    .col(ColumnDef::new(SystemSettings::Description).string())
                    .col(ColumnDef::new(SystemSettings::Category).string())
                    .col(ColumnDef::new(SystemSettings::CreatedAt).big_integer().not_null())
                    .col(ColumnDef::new(SystemSettings::UpdatedAt).big_integer().not_null())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(RefreshTokens::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Users::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(CommonPasswords::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(HibpCache::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(SystemConfig::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(SystemSettings::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
    Username,
    PasswordHash,
    CreatedAt,
    IsOwner,
    IsSystemAdmin,
    IsRoleAdmin,
    AppRoles,
    PasswordChangeRequired,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum RefreshTokens {
    Table,
    TokenHash,
    UserId,
    ExpiresAt,
    CreatedAt,
}

#[derive(DeriveIden)]
enum CommonPasswords {
    Table,
    Password,
}

#[derive(DeriveIden)]
enum HibpCache {
    Table,
    HashPrefix,
    ResponseData,
    FetchedAt,
}

#[derive(DeriveIden)]
enum SystemConfig {
    Table,
    Id,
    OwnerActive,
    UpdatedAt,
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