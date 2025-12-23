pub use sea_orm_migration::prelude::*;

mod m20250201_000001_create_auth_tables;
mod m20250201_000002_create_audit_tables;

pub struct AuthMigrator;

#[async_trait::async_trait]
impl MigratorTrait for AuthMigrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20250201_000001_create_auth_tables::Migration),
        ]
    }
}

pub struct AuditMigrator;

#[async_trait::async_trait]
impl MigratorTrait for AuditMigrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20250201_000002_create_audit_tables::Migration),
        ]
    }
}
