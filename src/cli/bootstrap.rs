use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};

use crate::types::db::user;

struct SeedUser {
    username: &'static str,
    password: &'static str,
    is_owner: bool,
    is_system_admin: bool,
    is_role_admin: bool,
}

const SEED_USERS: [SeedUser; 3] = [
    SeedUser {
        username: "owner",
        password: "owner-dev-password-change-me",
        is_owner: true,
        is_system_admin: false,
        is_role_admin: false,
    },
    SeedUser {
        username: "admin",
        password: "admin-dev-password-change-me",
        is_owner: false,
        is_system_admin: true,
        is_role_admin: false,
    },
    SeedUser {
        username: "user",
        password: "user-dev-password-change-me",
        is_owner: false,
        is_system_admin: false,
        is_role_admin: false,
    },
];

fn hash_password(password: &str) -> Result<String, Box<dyn std::error::Error>> {
    let salt = SaltString::generate(&mut rand_core::OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("Failed to hash password: {}", e))?
        .to_string();
    Ok(hash)
}

async fn user_exists(
    db: &DatabaseConnection,
    username: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let result = user::Entity::find()
        .filter(user::Column::Username.eq(username))
        .one(db)
        .await?;
    Ok(result.is_some())
}

pub async fn run(db: &DatabaseConnection) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Linkstash Bootstrap ===\n");

    let mut created = 0u32;
    let mut skipped = 0u32;

    for seed in &SEED_USERS {
        if user_exists(db, seed.username).await? {
            println!("Skipped '{}': already exists", seed.username);
            skipped += 1;
            continue;
        }

        let id = uuid::Uuid::new_v4().to_string();
        let password_hash = hash_password(seed.password)?;
        let now = chrono::Utc::now().timestamp();

        let model = user::ActiveModel {
            id: Set(id),
            username: Set(seed.username.to_string()),
            password_hash: Set(Some(password_hash)),
            created_at: Set(now),
            is_owner: Set(seed.is_owner),
            is_system_admin: Set(seed.is_system_admin),
            is_role_admin: Set(seed.is_role_admin),
            app_roles: Set(None),
            password_change_required: Set(false),
            updated_at: Set(now),
        };

        user::Entity::insert(model).exec(db).await?;

        println!("Created '{}' with password '{}'", seed.username, seed.password);
        created += 1;
    }

    println!("\n=== Bootstrap Complete ===");
    println!("Created: {}, Skipped: {}", created, skipped);

    Ok(())
}
