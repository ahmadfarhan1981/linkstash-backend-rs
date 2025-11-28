# Implementation Plan - Incremental Testing Approach

**Note:** This spec implements API endpoints for managing admin roles. It depends on the admin-role-system spec being completed first (database schema, JWT claims, store methods).

**Architecture:** This implementation follows the AppData pattern where all stores and stateless services are created once in main.rs and shared across services. AdminService will be created using `AdminService::new(app_data)` which extracts only the dependencies it needs. See `docs/appdata-pattern.md` for details.

**Strategy:** Tasks are organized to enable testing after each major feature is complete, rather than waiting until the end. Each phase is independently testable.

---

## Phase 0: Prerequisites Check

**Note:** Phase 0 from the original plan (owner_active login check) has already been implemented in the admin-role-system spec. The system_config_store is already integrated into AuthService via AppData pattern. This phase verifies the prerequisites are in place.

### Task 0.1: Verify admin-role-system prerequisites
- [x] Verify `system_config_store` exists in AppData
- [x] Verify `credential_store.set_privileges()` method exists
- [x] Verify `AdminFlags` type exists in `src/types/internal/auth.rs`
- [x] Verify `AdminError` type exists in `src/errors/admin.rs`
- [x] _Requirements: Dependencies from admin-role-system spec_
- [x] _Testable: All prerequisite types and methods are available_

### Task 0.2: Test prerequisites
- [x]* Write test: Can create AdminFlags with all three flags
- [x]* Write test: Can call credential_store.set_privileges() successfully
- [x]* Write test: AdminError variants exist and have correct status codes
- [x]* **✅ PHASE 0 COMPLETE - Prerequisites verified**

---

## Phase 1: Shared API Infrastructure

### Task 1.1: Create API helpers module
- [x] Create `src/api/helpers.rs`
- [x] Implement `extract_ip_address(req: &Request) -> Option<String>`
- [x] Implement `create_request_context(req, auth, token_service) -> RequestContext`
- [x] Export helpers from `src/api/mod.rs`
- [x] _Requirements: Design refactoring decision_
- [x] _Testable: Helper functions work correctly_

### Task 1.2: Test API helpers
- [x]* Write test: `extract_ip_address` from X-Forwarded-For header
- [x]* Write test: `extract_ip_address` from X-Real-IP header
- [x]* Write test: `extract_ip_address` from remote address
- [x]* Write test: `create_request_context` with valid JWT
- [x]* Write test: `create_request_context` with invalid JWT
- [x]* Write test: `create_request_context` without auth
- [x]* **✅ PHASE 1 COMPLETE - Shared helpers are working**

### Task 1.3: Migrate AuthApi to use helpers
- [x] Update `AuthApi` to use `helpers::create_request_context()`
- [x] Remove duplicate `create_request_context()` method from AuthApi
- [x] Remove duplicate `extract_ip_address()` method from AuthApi
- [x] Update all AuthApi endpoints to use helpers
- [x] Verify all existing AuthApi tests still pass
- [x] _Requirements: Design refactoring decision_
- [x] _Testable: AuthApi still works after migration_

---

## Phase 2: Token Invalidation Infrastructure

### Task 2.1: Add token invalidation to CredentialStore
- [x] Add `invalidate_all_tokens(&self, user_id: &str) -> Result<(), AuthError>` method
- [x] Use `RefreshToken::delete_many().filter(Column::UserId.eq(user_id))`
- [x] _Requirements: 4.1, 4.2_
- [x] _Testable: Can delete all tokens for a user_

### Task 2.2: Test token invalidation
- [x]* Write test: `invalidate_all_tokens` deletes all refresh tokens for user
- [x]* Write test: `invalidate_all_tokens` doesn't affect other users' tokens
- [x]* Write test: `invalidate_all_tokens` succeeds even if user has no tokens
- [x]* **✅ PHASE 2 COMPLETE - Token invalidation is working**

---

## Phase 3: Admin Error Types

### Task 3.1: Add OwnerOrSystemAdminRequired error variant
- [x] Add `OwnerOrSystemAdminRequired(Json<AdminErrorResponse>)` to AdminError enum
- [x] Add `owner_or_system_admin_required()` helper method
- [x] Update `message()` method to handle new variant
- [x] _Requirements: 6.3, 6.4, 8.1_
- [x] _Testable: Error can be created and formatted_

### Task 3.2: Add From implementations for error conversion
- [x] Add `impl From<sea_orm::DbErr> for AdminError`
- [x] Add `impl From<AuthError> for AdminError`
- [x] _Requirements: 8.4_
- [x] _Testable: Errors convert correctly_

### Task 3.3: Test admin error types
- [x]* Write test: All error variants have correct status codes
- [x]* Write test: Error messages are formatted correctly
- [x]* Write test: Error conversion from DbErr works
- [x]* Write test: Error conversion from AuthError works
- [x]* **✅ PHASE 3 COMPLETE - Error handling is ready**

---

## Phase 4: AdminService - System Admin Management

### Task 4.1: Create AdminService struct and constructor
- [x] Create `src/services/admin_service.rs`
- [x] Define AdminService struct with credential_store, system_config_store, token_service, audit_store fields
- [x] Implement `new(app_data: Arc<AppData>) -> Self` constructor that extracts dependencies from AppData
- [x] Implement `token_service()` getter method
- [x] Export AdminService from `src/services/mod.rs`
- [x] _Requirements: 1.1, 1.2_
- [x] _Testable: AdminService can be instantiated from AppData_

### Task 4.2: Implement assign_system_admin method
- [x] Extract claims from context, check authentication
- [x] Check authorization: `claims.is_owner` must be true
- [x] Check self-modification: `claims.sub != target_user_id`
- [x] Get current user to build AdminFlags with is_system_admin=true
- [x] Call `credential_store.set_privileges()` with new flags
- [x] Call `credential_store.invalidate_all_tokens(target_user_id)`
- [x] _Requirements: 1.1, 3.1, 3.2, 4.1, 4.2, 4.3, 6.1, 7.1_
- [x] _Testable: System Admin role can be assigned_

### Task 4.3: Implement remove_system_admin method
- [x] Same authorization and self-modification checks as assign
- [x] Call `credential_store.set_privileges()` with is_system_admin=false
- [x] Call `credential_store.invalidate_all_tokens(target_user_id)`
- [x] _Requirements: 1.2, 3.1, 3.2, 4.1, 4.2, 4.3, 6.1, 7.2_
- [x] _Testable: System Admin role can be removed_
- [x]* **✅ PHASE 4 COMPLETE - System Admin management implemented**

---

## Phase 5: AdminService - Role Admin Management

### Task 5.1: Implement assign_role_admin method
- [x] Extract claims from context, check authentication
- [x] Check authorization: `claims.is_owner OR claims.is_system_admin` must be true
- [x] Check self-modification: `claims.sub != target_user_id`
- [x] Get current user to build AdminFlags with is_role_admin=true
- [x] Call `credential_store.set_privileges()` with new flags
- [x] Call `credential_store.invalidate_all_tokens(target_user_id)`
- [x] _Requirements: 1.3, 2.1, 3.1, 3.2, 4.1, 4.2, 4.3, 6.3, 7.3_
- [x] _Testable: Role Admin role can be assigned_

### Task 5.2: Implement remove_role_admin method
- [x] Same authorization and self-modification checks as assign
- [x] Call `credential_store.set_privileges()` with is_role_admin=false
- [x] Call `credential_store.invalidate_all_tokens(target_user_id)`
- [x] _Requirements: 1.4, 2.2, 3.1, 3.2, 4.1, 4.2, 4.3, 6.4, 7.4_
- [x] _Testable: Role Admin role can be removed_
- [x]* **✅ PHASE 5 COMPLETE - Role Admin management implemented**

---

## Phase 6: AdminService - Owner Deactivation

### Task 6.1: Implement deactivate_owner method
- [x] Extract claims from context, check authentication
- [x] Check authorization: `claims.is_owner` must be true
- [x] Call `system_config_store.set_owner_active(false, Some(claims.sub), ctx.ip_address)`
- [x] Get owner user from credential_store
- [x] Call `credential_store.invalidate_all_tokens(owner_user_id)`
- [x] _Requirements: 5.1, 5.2, 5.3, 7.6_
- [x] _Testable: Owner can deactivate themselves_
- [x]* **✅ PHASE 6 COMPLETE - Owner deactivation implemented**

---

## Phase 7: AdminApi - DTOs and Structure

### Task 7.1: Create admin DTOs
- [x] Create `src/types/dto/admin.rs`
- [x] Define `AssignRoleRequest` with `target_user_id` field
- [x] Define `AssignRoleResponse` with `success` and `message` fields
- [x] Define `RemoveRoleRequest` with `target_user_id` field
- [x] Define `RemoveRoleResponse` with `success` and `message` fields
- [x] Define `DeactivateResponse` with `success` and `message` fields
- [x] Export from `src/types/dto/mod.rs`
- [x] _Requirements: All API requirements_
- [x] _Testable: DTOs can be serialized/deserialized_

### Task 7.2: Create AdminApi struct
- [x] Create `src/api/admin.rs`
- [x] Define AdminApi struct with `admin_service` field
- [x] Implement `new(admin_service)` constructor
- [x] Add AdminTags enum for OpenAPI
- [x] Export from `src/api/mod.rs`
- [x] _Requirements: All API requirements_
- [x] _Testable: AdminApi can be instantiated_
- [x]* **✅ PHASE 7 COMPLETE - DTOs and AdminApi structure ready**

---

## Phase 8: AdminApi - System Admin Endpoints

### Task 8.1: Implement POST /api/admin/roles/system-admin endpoint
- [x] Use `helpers::create_request_context()` to create context
- [x] Check `ctx.authenticated`, return 401 if false
- [x] Call `admin_service.assign_system_admin(&ctx, &body.target_user_id)`
- [x] Convert AdminError to poem::Error
- [x] Return success response
- [x] _Requirements: 1.1, 6.1, 7.1_
- [x] _Testable: Endpoint assigns System Admin role_

### Task 8.2: Implement DELETE /api/admin/roles/system-admin endpoint
- [x] Use `helpers::create_request_context()` to create context
- [x] Check `ctx.authenticated`, return 401 if false
- [x] Call `admin_service.remove_system_admin(&ctx, &body.target_user_id)`
- [x] Convert AdminError to poem::Error
- [x] Return success response
- [x] _Requirements: 1.2, 6.1, 7.2_
- [x] _Testable: Endpoint removes System Admin role_
- [x]* **✅ PHASE 8 COMPLETE - System Admin endpoints implemented**



---

## Phase 9: AdminApi - Role Admin Endpoints

### Task 9.1: Implement POST /api/admin/roles/role-admin endpoint
- [x] Use `helpers::create_request_context()` to create context
- [x] Check `ctx.authenticated`, return 401 if false
- [x] Call `admin_service.assign_role_admin(&ctx, &body.target_user_id)`
- [x] Convert AdminError to poem::Error
- [x] Return success response
- [x] _Requirements: 1.3, 2.1, 6.3, 7.3_
- [x] _Testable: Endpoint assigns Role Admin role_

### Task 9.2: Implement DELETE /api/admin/roles/role-admin endpoint
- [x] Use `helpers::create_request_context()` to create context
- [x] Check `ctx.authenticated`, return 401 if false
- [x] Call `admin_service.remove_role_admin(&ctx, &body.target_user_id)`
- [x] Convert AdminError to poem::Error
- [x] Return success response
- [x] _Requirements: 1.4, 2.2, 6.4, 7.4_
- [x] _Testable: Endpoint removes Role Admin role_
- [x]* **✅ PHASE 9 COMPLETE - Role Admin endpoints implemented**



---

## Phase 10: AdminApi - Owner Deactivation Endpoint

### Task 10.1: Implement POST /api/admin/owner/deactivate endpoint
- [x] Use `helpers::create_request_context()` to create context
- [x] Check `ctx.authenticated`, return 401 if false
- [x] Call `admin_service.deactivate_owner(&ctx)`
- [x] Convert AdminError to poem::Error
- [x] Return success response
- [x] _Requirements: 5.1, 5.2, 5.3_
- [x] _Testable: Endpoint deactivates owner_
- [x]* **✅ PHASE 10 COMPLETE - Owner deactivation endpoint implemented**



---

## Phase 11: Integration and Registration

### Task 11.1: Register AdminApi in main.rs
- [x] In main.rs, after creating auth_service, create AdminService: `let admin_service = Arc::new(AdminService::new(app_data.clone()))`
- [x] Create AdminApi instance: `let admin_api = AdminApi::new(admin_service)`
- [x] Add admin_api to OpenApiService tuple: `OpenApiService::new((HealthApi, auth_api, admin_api), ...)`
- [x] Verify server starts successfully without errors
- [x] _Requirements: All API requirements_
- [x] _Testable: Server starts and Swagger UI shows admin endpoints at /swagger_
- [x]* **✅ PHASE 11 COMPLETE - AdminApi registered and server working**



---

## Phase 12: Documentation

### Task 12.1: Create authorization and user levels documentation
- [x] Create `docs/authorization-and-user-levels.md` with comprehensive overview
- [x] Document all user levels: Regular User, Role Admin, System Admin, Owner
- [x] For each level, document concrete capabilities (what API endpoints they can access)
- [x] Create authorization matrix table showing who can perform which operations
- [x] Explain design rationale: why this hierarchy, why owner is inactive by default, separation of concerns
- [x] Document self-modification prevention and why it exists
- [x] Link to Swagger UI for detailed API endpoint documentation
- [x] _Requirements: All requirements_
- [x] _Rationale: Fills documentation gap - no existing doc covers regular users or provides authorization matrix. Helps developers understand the authorization model when extending the system._

### Task 12.2: Update bootstrap documentation with API reference
- [x] Update `docs/bootstrap-and-owner-management.md` to add brief section on post-bootstrap role management
- [x] Document that admin roles can be assigned/removed via REST API after bootstrap
- [x] Reference the new `authorization-and-user-levels.md` for details on who can do what
- [x] Add note that Swagger UI at `/swagger` provides interactive API documentation
- [x] _Requirements: All requirements_
- [x] _Rationale: Bootstrap doc should mention API exists, but detailed authorization info belongs in dedicated doc._
- [x]* **✅ PHASE 12 COMPLETE - Documentation updated**
