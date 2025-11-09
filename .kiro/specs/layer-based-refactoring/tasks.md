# Implementation Plan

- [x] 1. Create new directory structure

  - Create all new layer directories with placeholder mod.rs files
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

- [x] 1.1 Create api/ directory structure


  - Create `src/api/` directory
  - Create `src/api/mod.rs` with placeholder exports
  - _Requirements: 1.1_

- [x] 1.2 Create types/ directory structure


  - Create `src/types/` directory
  - Create `src/types/db/` directory
  - Create `src/types/dto/` directory
  - Create `src/types/internal/` directory
  - Create placeholder `mod.rs` files in each subdirectory
  - _Requirements: 1.4, 2.1, 2.2, 2.3_

- [x] 1.3 Create services/ directory structure


  - Create `src/services/` directory
  - Create `src/services/mod.rs` with placeholder exports
  - _Requirements: 1.2_

- [x] 1.4 Create stores/ directory structure


  - Create `src/stores/` directory
  - Create `src/stores/mod.rs` with placeholder exports
  - _Requirements: 1.3_

- [x] 1.5 Create errors/ directory structure


  - Create `src/errors/` directory
  - Create `src/errors/mod.rs` with placeholder exports
  - _Requirements: 1.5_

- [x] 2. Migrate database entities to types/db/

  - Move SeaORM entity files to types/db/ and update module exports
  - _Requirements: 2.1, 2.4, 4.1, 4.2, 4.3_

- [x] 2.1 Move user entity


  - Copy `src/auth/entities/user.rs` to `src/types/db/user.rs`
  - Update `src/types/db/mod.rs` to export user module
  - Update `src/types/mod.rs` to export db module
  - _Requirements: 2.1, 2.4_

- [x] 2.2 Move refresh_token entity


  - Copy `src/auth/entities/refresh_token.rs` to `src/types/db/refresh_token.rs`
  - Update entity relation imports to use `super::user::Entity`
  - Update `src/types/db/mod.rs` to export refresh_token module
  - _Requirements: 2.1, 2.4_

- [x] 2.3 Update credential_store imports for entities


  - Update `src/auth/credential_store.rs` to import from `crate::types::db`
  - Replace `crate::auth::entities::user` with `crate::types::db::user`
  - Replace `crate::auth::entities::refresh_token` with `crate::types::db::refresh_token`
  - Verify code compiles with `cargo build`
  - _Requirements: 4.1, 4.2, 4.5_


- [x] 3. Migrate DTOs to types/dto/

  - Extract and move API request/response types to types/dto/
  - _Requirements: 2.2, 2.5, 4.1, 4.2, 4.3_



- [x] 3.1 Create auth DTOs

  - Extract `LoginRequest`, `TokenResponse`, `WhoAmIResponse`, `RefreshRequest`, `RefreshResponse` from `src/auth/models.rs`
  - Create `src/types/dto/auth.rs` with these types


  - Update `src/types/dto/mod.rs` to export auth module
  - _Requirements: 2.2, 2.5_

- [x] 3.2 Create items DTOs


  - Extract `CreateItemRequest`, `Item` from `src/models.rs`
  - Create `src/types/dto/items.rs` with these types
  - Update `src/types/dto/mod.rs` to export items module
  - _Requirements: 2.2, 2.5_




- [ ] 3.3 Create common DTOs
  - Extract `HealthResponse`, `ErrorResponse` from `src/models.rs`
  - Create `src/types/dto/common.rs` with these types


  - Update `src/types/dto/mod.rs` to export common module
  - _Requirements: 2.2, 2.5_


- [ ] 3.4 Update auth API imports for DTOs
  - Update `src/auth/api.rs` to import from `crate::types::dto::auth`
  - Replace local model imports with `types::dto::auth::*`
  - Verify code compiles with `cargo build`


  - _Requirements: 4.1, 4.2, 4.5_

- [ ] 3.5 Update root API imports for DTOs
  - Update `src/api.rs` to import from `crate::types::dto::{items, common}`
  - Replace local model imports with types::dto paths
  - Verify code compiles with `cargo build`
  - _Requirements: 4.1, 4.2, 4.5_

- [x] 4. Migrate internal types to types/internal/

  - Move internal-only types like Claims to types/internal/
  - _Requirements: 2.3, 2.5, 4.1, 4.2_

- [x] 4.1 Create internal auth types

  - Extract `Claims` from `src/auth/models.rs`
  - Create `src/types/internal/auth.rs` with Claims struct
  - Update `src/types/internal/mod.rs` to export auth module
  - Update `src/types/mod.rs` to export internal module
  - _Requirements: 2.3, 2.5_

- [x] 4.2 Update token_manager imports for Claims


  - Update `src/auth/token_manager.rs` to import from `crate::types::internal::auth`
  - Replace `super::Claims` with `types::internal::auth::Claims`
  - Verify code compiles with `cargo build`
  - _Requirements: 4.1, 4.2, 4.5_

- [x] 4.3 Update auth API imports for Claims


  - Update `src/auth/api.rs` test imports to use `crate::types::internal::auth::Claims`
  - Verify tests compile and pass with `cargo test`
  - _Requirements: 4.1, 4.2, 4.5_

- [x] 5. Migrate errors to errors/

  - Move error types to dedicated errors/ layer
  - _Requirements: 1.5, 4.1, 4.2, 4.3_

- [x] 5.1 Move AuthError


  - Copy `src/auth/errors.rs` to `src/errors/auth.rs`
  - Update `src/errors/mod.rs` to export auth module
  - _Requirements: 1.5_

- [x] 5.2 Update all imports for AuthError


  - Update `src/auth/credential_store.rs` to import from `crate::errors::auth`
  - Update `src/auth/token_manager.rs` to import from `crate::errors::auth`
  - Update `src/auth/api.rs` to import from `crate::errors::auth`
  - Update `src/main.rs` to import from `crate::errors::auth`
  - Verify code compiles with `cargo build`
  - _Requirements: 4.1, 4.2, 4.5_

- [x] 6. Migrate stores to stores/

  - Move data access layer to stores/
  - _Requirements: 1.3, 6.1, 6.2, 6.3, 6.4, 6.5, 7.3, 4.1, 4.2_

- [x] 6.1 Move credential_store


  - Copy `src/auth/credential_store.rs` to `src/stores/credential_store.rs`
  - Update `src/stores/mod.rs` to export credential_store module

  - _Requirements: 1.3, 6.1, 6.2, 6.3_



- [ ] 6.2 Update credential_store imports
  - Ensure imports use `crate::types::db::*` for entities
  - Ensure imports use `crate::errors::auth::AuthError`
  - Verify all SeaORM usage is contained within this file

  - Verify code compiles with `cargo build`


  - _Requirements: 6.5, 7.3, 4.1, 4.2, 4.5_

- [ ] 6.3 Update main.rs to use stores
  - Update `src/main.rs` to import `CredentialStore` from `crate::stores::credential_store`



  - Remove `auth::CredentialStore` import
  - Verify code compiles with `cargo build`
  - _Requirements: 4.1, 4.2, 4.4, 4.5_

- [ ] 6.4 Update auth API to use stores
  - Update `src/auth/api.rs` to import `CredentialStore` from `crate::stores::credential_store`
  - Remove local credential_store import

  - Verify tests compile and pass with `cargo test`
  - _Requirements: 4.1, 4.2, 4.5_

- [x] 7. Migrate services to services/

  - Move business logic to services/ and rename TokenManager to TokenService
  - _Requirements: 1.2, 7.2, 4.1, 4.2_

- [x] 7.1 Move and rename token_manager to token_service

  - Copy `src/auth/token_manager.rs` to `src/services/token_service.rs`
  - Rename struct `TokenManager` to `TokenService` throughout the file
  - Update `src/services/mod.rs` to export token_service module
  - _Requirements: 1.2, 7.2_

- [x] 7.2 Update token_service imports


  - Ensure imports use `crate::types::internal::auth::Claims`
  - Ensure imports use `crate::errors::auth::AuthError`
  - Verify code compiles with `cargo build`
  - _Requirements: 4.1, 4.2, 4.5_

- [x] 7.3 Update main.rs to use TokenService


  - Update `src/main.rs` to import `TokenService` from `crate::services::token_service`
  - Replace `TokenManager::new()` with `TokenService::new()`
  - Replace `Arc<TokenManager>` with `Arc<TokenService>`
  - Remove `auth::TokenManager` import
  - Verify code compiles with `cargo build`
  - _Requirements: 4.1, 4.2, 4.4, 4.5_

- [x] 7.4 Update auth API to use TokenService


  - Update `src/auth/api.rs` to import `TokenService` from `crate::services::token_service`
  - Replace `TokenManager` with `TokenService` in struct fields and constructor
  - Replace `Arc<TokenManager>` with `Arc<TokenService>`
  - Update all test code to use `TokenService`
  - Verify tests compile and pass with `cargo test`
  - _Requirements: 4.1, 4.2, 4.5_

- [x] 8. Migrate API endpoints to api/

  - Split and move all API endpoint implementations to api/
  - _Requirements: 1.1, 7.1, 4.1, 4.2, 4.3_

- [x] 8.1 Create health API


  - Extract health endpoint from `src/api.rs`
  - Create `src/api/health.rs` with `HealthApi` struct and health endpoint
  - Include `ApiTags::Health` enum in the file
  - Update `src/api/mod.rs` to export health module
  - _Requirements: 1.1, 7.1_

- [x] 8.2 Create items API


  - Extract items endpoint from `src/api.rs`
  - Create `src/api/items.rs` with `ItemsApi` struct and create_item endpoint
  - Include `ApiTags::Items` enum in the file
  - Update `src/api/mod.rs` to export items module
  - _Requirements: 1.1, 7.1_

- [x] 8.3 Move auth API


  - Copy `src/auth/api.rs` to `src/api/auth.rs`
  - Update imports to use `crate::types::dto::auth::*`
  - Update imports to use `crate::errors::auth::AuthError`
  - Update imports to use `crate::stores::credential_store::CredentialStore`
  - Update imports to use `crate::services::token_service::TokenService`
  - Update `src/api/mod.rs` to export auth module
  - Verify code compiles with `cargo build`
  - _Requirements: 1.1, 7.1, 4.1, 4.2, 4.5_

- [x] 8.4 Update main.rs to use new API structure


  - Update `src/main.rs` module declarations to include `mod api;`
  - Remove `mod auth;` declaration
  - Import `HealthApi` from `crate::api::health`
  - Import `ItemsApi` from `crate::api::items`
  - Import `AuthApi` from `crate::api::auth`
  - Update `OpenApiService::new()` to use `(HealthApi, ItemsApi, AuthApi)`
  - Verify code compiles with `cargo build`
  - _Requirements: 4.1, 4.2, 4.4, 4.5_

- [x] 9. Clean up old structure

  - Remove old feature-based directories and files
  - _Requirements: 5.5, 3.1, 3.2, 3.3, 3.4, 3.5_

- [x] 9.1 Remove old auth module


  - Delete `src/auth/` directory and all its contents
  - Verify code still compiles with `cargo build`
  - _Requirements: 5.5_

- [x] 9.2 Remove old root files




  - Delete `src/models.rs`
  - Delete `src/api.rs`
  - Update `src/main.rs` to remove any remaining references to these files
  - Verify code compiles with `cargo build`
  - _Requirements: 5.5_

- [ ] 10. Final verification and testing


  - Run comprehensive tests to ensure all functionality is preserved
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 4.5, 5.1, 5.2, 5.3, 5.4_

- [x] 10.1 Run full test suite


  - Execute `cargo test` to run all unit and integration tests
  - Verify all tests pass without errors
  - _Requirements: 3.2_

- [x] 10.2 Build release binary


  - Execute `cargo build --release`
  - Verify build succeeds without warnings
  - _Requirements: 3.1_

- [x] 10.3 Manual server testing


  - Start the server with `cargo run` (set JWT_SECRET environment variable)
  - Verify server starts successfully on port 3000
  - Access Swagger UI at http://localhost:3000/swagger
  - Verify all endpoints are documented correctly
  - Test health endpoint: GET /api/health
  - Test login endpoint: POST /api/auth/login
  - Test whoami endpoint: GET /api/auth/whoami (with JWT)
  - Test refresh endpoint: POST /api/auth/refresh
  - _Requirements: 3.3, 3.4, 3.5, 5.3_

- [x] 10.4 Verify layer separation


  - Search codebase for SeaORM imports outside stores/ and types/db/
  - Verify no circular dependencies between layers
  - Verify dependency flow: API → Services → Stores → Entities
  - Confirm all requirements from 6.5 and 7.3 are met
  - _Requirements: 6.5, 7.3, 7.4, 7.5_
