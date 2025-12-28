use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create audit_events table with new RequestContext field
        manager
            .create_table(
                Table::create()
                    .table(AuditEvents::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(AuditEvents::Id).big_integer().not_null().auto_increment().primary_key())
                    .col(ColumnDef::new(AuditEvents::Timestamp).string().not_null())
                    .col(ColumnDef::new(AuditEvents::EventType).string().not_null())    
                    .col(ColumnDef::new(AuditEvents::UserId).string().not_null())
                    .col(ColumnDef::new(AuditEvents::IpAddress).string())
                    .col(ColumnDef::new(AuditEvents::JwtId).string())
                    .col(ColumnDef::new(AuditEvents::Data).string().not_null()) // JSON string
                    .index(
                        Index::create()
                            .name("idx_audit_events_user_id")
                            .col(AuditEvents::UserId)
                    )
                    .index(
                        Index::create()
                            .name("idx_audit_events_event_type")
                            .col(AuditEvents::EventType)
                    )
                    .index(
                        Index::create()
                            .name("idx_audit_events_timestamp")
                            .col(AuditEvents::Timestamp)
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(AuditEvents::Table).to_owned())
            .await?;

        Ok(())
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