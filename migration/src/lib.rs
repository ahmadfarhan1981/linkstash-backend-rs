pub use sea_orm_migration::prelude::*;

mod m20250123_000001_create_auth_schema;
mod m20250123_000002_create_audit_schema;
mod m20250127_000001_create_common_passwords;
mod m20250127_000002_create_hibp_cache;
mod m20250127_000003_add_password_change_required;

pub struct AuthMigrator;

#[async_trait::async_trait]
impl MigratorTrait for AuthMigrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20250123_000001_create_auth_schema::Migration),
            Box::new(m20250127_000001_create_common_passwords::Migration),
            Box::new(m20250127_000002_create_hibp_cache::Migration),
            Box::new(m20250127_000003_add_password_change_required::Migration),
        ]
    }
}

pub struct AuditMigrator;

#[async_trait::async_trait]
impl MigratorTrait for AuditMigrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20250123_000002_create_audit_schema::Migration),
        ]
    }
}
