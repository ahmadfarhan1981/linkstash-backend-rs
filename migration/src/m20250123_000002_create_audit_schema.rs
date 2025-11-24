use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create audit_events table
        manager
            .create_table(
                Table::create()
                    .table(AuditEvents::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AuditEvents::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(AuditEvents::Timestamp)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AuditEvents::EventType)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AuditEvents::UserId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AuditEvents::IpAddress)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(AuditEvents::JwtId)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(AuditEvents::Data)
                            .string()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Create index on timestamp for time-range queries
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_audit_timestamp")
                    .table(AuditEvents::Table)
                    .col(AuditEvents::Timestamp)
                    .to_owned(),
            )
            .await?;

        // Create index on event_type for filtering by event type
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_audit_event_type")
                    .table(AuditEvents::Table)
                    .col(AuditEvents::EventType)
                    .to_owned(),
            )
            .await?;

        // Create index on user_id for filtering by user
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_audit_user_id")
                    .table(AuditEvents::Table)
                    .col(AuditEvents::UserId)
                    .to_owned(),
            )
            .await?;

        // Create index on jwt_id for tracking token lifecycle
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_audit_jwt_id")
                    .table(AuditEvents::Table)
                    .col(AuditEvents::JwtId)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(AuditEvents::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum AuditEvents {
    Table,
    Id,
    Timestamp,
    EventType,
    UserId,
    IpAddress,
    JwtId,
    Data,
}
