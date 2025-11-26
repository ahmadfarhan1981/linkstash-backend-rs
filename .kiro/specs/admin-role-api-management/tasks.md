# Implementation Plan - Incremental Testing Approach

**Note:** This spec implements API endpoints for managing admin roles. It depends on the admin-role-system spec being completed first (database schema, JWT claims, store methods).

**Strategy:** Tasks are organized to enable testing after each major feature is complete, rather than waiting until the end. Each phase is independently testable.

---

## Phase 0: Critical Security Fix (MUST DO FIRST)

### Task 0.1: Add SystemConfigStore to AuthService
- [ ] Add `system_config_store: Arc<SystemConfigStore>` field to AuthService struct
- [ ] Update `AuthService::init()` to create SystemConfigStore
- [ ] Update `AuthService::new()` constructor to accept system_config_store parameter
- [ ] _Requirements: From admin-role-system spec 3.1, 3.2, 3.3_
- [ ] _Testable: Verify AuthService can be instantiated with system_config_store_

### Task 0.2: Implement owner_active login check
- [ ] In `AuthService::login()`, after fetching user data, check if `user.is_owner == true`
- [ ] If owner, call `system_config_store.is_owner_active().await?`
- [ ] If `owner_active == false`, log rejection and return `AuthError::invalid_credentials()`
- [ ] _Requirements: From admin-role-system spec 3.1, 3.2, 3.3_
- [ ] _Testable: Owner login behavior_

### Task 0.3: Add audit logging for owner login rejection
- [ ] Add `log_owner_login_rejected()` to audit_logger if not exists
- [ ] Call audit logger when owner login is rejected due to owner_active=false
- [ ] _Requirements: From admin-role-system spec 3.3_
- [ ] _Testable: Audit logs contain rejection events_

### Task 0.4: Test owner_active login check
- [ ]* Write test: Owner with owner_active=false cannot login
- [ ]* Write test: Owner with owner_active=true can login
- [ ]* Write test: Regular user login unaffected by owner_active flag
- [ ]* Write test: Failed owner login attempts are logged to audit database
- [ ]* _Requirements: From admin-role-system spec 3.1, 3.2, 3.3_
- [ ]* **✅ PHASE 0 COMPLETE - Owner active check is working**

---

## Phase 1: Shared API Infrastructure

### Task 1.1: Create API helpers module
- [ ] Create `src/api/helpers.rs`
- [ ] Implement `extract_ip_address(req: &Request) -> Option<String>`
- [ ] Implement `create_request_context(req, auth, token_service) -> RequestContext`
- [ ] Export helpers from `src/api/mod.rs`
- [ ] _Requirements: Design refactoring decision_
- [ ] _Testable: Helper functions work correctly_

### Task 1.2: Test API helpers
- [ ]* Write test: `extract_ip_address` from X-Forwarded-For header
- [ ]* Write test: `extract_ip_address` from X-Real-IP header
- [ ]* Write test: `extract_ip_address` from remote address
- [ ]* Write test: `create_request_context` with valid JWT
- [ ]* Write test: `create_request_context` with invalid JWT
- [ ]* Write test: `create_request_context` without auth
- [ ]* **✅ PHASE 1 COMPLETE - Shared helpers are working**

### Task 1.3: Migrate AuthApi to use helpers
- [ ] Update `AuthApi` to use `helpers::create_request_context()`
- [ ] Remove duplicate `create_request_context()` method from AuthApi
- [ ] Remove duplicate `extract_ip_address()` method from AuthApi
- [ ] Update all AuthApi endpoints to use helpers
- [ ] Verify all existing AuthApi tests still pass
- [ ] _Requirements: Design refactoring decision_
- [ ] _Testable: AuthApi still works after migration_

---

## Phase 2: Token Invalidation Infrastructure

### Task 2.1: Add token invalidation to CredentialStore
- [ ] Add `invalidate_all_tokens(&self, user_id: &str) -> Result<(), AuthError>` method
- [ ] Use `RefreshToken::delete_many().filter(Column::UserId.eq(user_id))`
- [ ] _Requirements: 4.1, 4.2_
- [ ] _Testable: Can delete all tokens for a user_

### Task 2.2: Test token invalidation
- [ ]* Write test: `invalidate_all_tokens` deletes all refresh tokens for user
- [ ]* Write test: `invalidate_all_tokens` doesn't affect other users' tokens
- [ ]* Write test: `invalidate_all_tokens` succeeds even if user has no tokens
- [ ]* **✅ PHASE 2 COMPLETE - Token invalidation is working**

---

## Phase 3: Admin Error Types

### Task 3.1: Add OwnerOrSystemAdminRequired error variant
- [ ] Add `OwnerOrSystemAdminRequired(Json<AdminErrorResponse>)` to AdminError enum
- [ ] Add `owner_or_system_admin_required()` helper method
- [ ] Update `message()` method to handle new variant
- [ ] _Requirements: 6.3, 6.4, 8.1_
- [ ] _Testable: Error can be created and formatted_

### Task 3.2: Add From implementations for error conversion
- [ ] Add `impl From<sea_orm::DbErr> for AdminError`
- [ ] Add `impl From<AuthError> for AdminError`
- [ ] _Requirements: 8.4_
- [ ] _Testable: Errors convert correctly_

### Task 3.3: Test admin error types
- [ ]* Write test: All error variants have correct status codes
- [ ]* Write test: Error messages are formatted correctly
- [ ]* Write test: Error conversion from DbErr works
- [ ]* Write test: Error conversion from AuthError works
- [ ]* **✅ PHASE 3 COMPLETE - Error handling is ready**

---

## Phase 4: AdminService - System Admin Management

### Task 4.1: Create AdminService struct and constructor
- [ ] Create `src/services/admin_service.rs`
- [ ] Define AdminService struct with credential_store, system_config_store, token_service, audit_store
- [ ] Implement `new()` constructor
- [ ] Implement `token_service()` getter
- [ ] Export from `src/services/mod.rs`
- [ ] _Requirements: 1.1, 1.2_
- [ ] _Testable: AdminService can be instantiated_

### Task 4.2: Implement assign_system_admin method
- [ ] Extract claims from context, check authentication
- [ ] Check authorization: `claims.is_owner` must be true
- [ ] Check self-modification: `claims.sub != target_user_id`
- [ ] Get current user to build AdminFlags with is_system_admin=true
- [ ] Call `credential_store.set_privileges()` with new flags
- [ ] Call `credential_store.invalidate_all_tokens(target_user_id)`
- [ ] _Requirements: 1.1, 3.1, 3.2, 4.1, 4.2, 4.3, 6.1, 7.1_
- [ ] _Testable: System Admin role can be assigned_

### Task 4.3: Implement remove_system_admin method
- [ ] Same authorization and self-modification checks as assign
- [ ] Call `credential_store.set_privileges()` with is_system_admin=false
- [ ] Call `credential_store.invalidate_all_tokens(target_user_id)`
- [ ] _Requirements: 1.2, 3.1, 3.2, 4.1, 4.2, 4.3, 6.1, 7.2_
- [ ] _Testable: System Admin role can be removed_

### Task 4.4: Test System Admin management
- [ ]* Write test: Owner can assign System Admin role
- [ ]* Write test: Owner can remove System Admin role
- [ ]* Write test: Non-owner cannot assign System Admin role
- [ ]* Write test: Cannot assign System Admin to self
- [ ]* Write test: Cannot remove System Admin from self
- [ ]* Write test: Tokens are invalidated after role change
- [ ]* Write test: User not found returns appropriate error
- [ ]* Write test: Audit logs capture role changes
- [ ]* **✅ PHASE 4 COMPLETE - System Admin management is working**

---

## Phase 5: AdminService - Role Admin Management

### Task 5.1: Implement assign_role_admin method
- [ ] Extract claims from context, check authentication
- [ ] Check authorization: `claims.is_owner OR claims.is_system_admin` must be true
- [ ] Check self-modification: `claims.sub != target_user_id`
- [ ] Get current user to build AdminFlags with is_role_admin=true
- [ ] Call `credential_store.set_privileges()` with new flags
- [ ] Call `credential_store.invalidate_all_tokens(target_user_id)`
- [ ] _Requirements: 1.3, 2.1, 3.1, 3.2, 4.1, 4.2, 4.3, 6.3, 7.3_
- [ ] _Testable: Role Admin role can be assigned_

### Task 5.2: Implement remove_role_admin method
- [ ] Same authorization and self-modification checks as assign
- [ ] Call `credential_store.set_privileges()` with is_role_admin=false
- [ ] Call `credential_store.invalidate_all_tokens(target_user_id)`
- [ ] _Requirements: 1.4, 2.2, 3.1, 3.2, 4.1, 4.2, 4.3, 6.4, 7.4_
- [ ] _Testable: Role Admin role can be removed_

### Task 5.3: Test Role Admin management
- [ ]* Write test: Owner can assign Role Admin role
- [ ]* Write test: Owner can remove Role Admin role
- [ ]* Write test: System Admin can assign Role Admin role
- [ ]* Write test: System Admin can remove Role Admin role
- [ ]* Write test: Regular user cannot assign Role Admin role
- [ ]* Write test: Cannot assign Role Admin to self
- [ ]* Write test: Cannot remove Role Admin from self
- [ ]* Write test: Tokens are invalidated after role change
- [ ]* Write test: Audit logs capture role changes
- [ ]* **✅ PHASE 5 COMPLETE - Role Admin management is working**

---

## Phase 6: AdminService - Owner Deactivation

### Task 6.1: Implement deactivate_owner method
- [ ] Extract claims from context, check authentication
- [ ] Check authorization: `claims.is_owner` must be true
- [ ] Call `system_config_store.set_owner_active(false, Some(claims.sub), ctx.ip_address)`
- [ ] Get owner user from credential_store
- [ ] Call `credential_store.invalidate_all_tokens(owner_user_id)`
- [ ] _Requirements: 5.1, 5.2, 5.3, 7.6_
- [ ] _Testable: Owner can deactivate themselves_

### Task 6.2: Test owner deactivation
- [ ]* Write test: Owner can deactivate their own account
- [ ]* Write test: Non-owner cannot deactivate owner
- [ ]* Write test: Owner tokens are invalidated after deactivation
- [ ]* Write test: Owner cannot login after deactivation
- [ ]* Write test: Audit logs capture owner deactivation
- [ ]* **✅ PHASE 6 COMPLETE - Owner deactivation is working**

---

## Phase 7: AdminApi - DTOs and Structure

### Task 7.1: Create admin DTOs
- [ ] Create `src/types/dto/admin.rs`
- [ ] Define `AssignRoleRequest` with `target_user_id` field
- [ ] Define `AssignRoleResponse` with `success` and `message` fields
- [ ] Define `RemoveRoleRequest` with `target_user_id` field
- [ ] Define `RemoveRoleResponse` with `success` and `message` fields
- [ ] Define `DeactivateResponse` with `success` and `message` fields
- [ ] Export from `src/types/dto/mod.rs`
- [ ] _Requirements: All API requirements_
- [ ] _Testable: DTOs can be serialized/deserialized_

### Task 7.2: Create AdminApi struct
- [ ] Create `src/api/admin.rs`
- [ ] Define AdminApi struct with `admin_service` field
- [ ] Implement `new(admin_service)` constructor
- [ ] Add AdminTags enum for OpenAPI
- [ ] Export from `src/api/mod.rs`
- [ ] _Requirements: All API requirements_
- [ ] _Testable: AdminApi can be instantiated_

---

## Phase 8: AdminApi - System Admin Endpoints

### Task 8.1: Implement POST /api/admin/roles/system-admin endpoint
- [ ] Use `helpers::create_request_context()` to create context
- [ ] Check `ctx.authenticated`, return 401 if false
- [ ] Call `admin_service.assign_system_admin(&ctx, &body.target_user_id)`
- [ ] Convert AdminError to poem::Error
- [ ] Return success response
- [ ] _Requirements: 1.1, 6.1, 7.1_
- [ ] _Testable: Endpoint assigns System Admin role_

### Task 8.2: Implement DELETE /api/admin/roles/system-admin endpoint
- [ ] Use `helpers::create_request_context()` to create context
- [ ] Check `ctx.authenticated`, return 401 if false
- [ ] Call `admin_service.remove_system_admin(&ctx, &body.target_user_id)`
- [ ] Convert AdminError to poem::Error
- [ ] Return success response
- [ ] _Requirements: 1.2, 6.1, 7.2_
- [ ] _Testable: Endpoint removes System Admin role_

### Task 8.3: Test System Admin endpoints
- [ ]* Write test: POST endpoint assigns System Admin role
- [ ]* Write test: DELETE endpoint removes System Admin role
- [ ]* Write test: Endpoints require authentication
- [ ]* Write test: Endpoints require owner role
- [ ]* Write test: Endpoints reject self-modification
- [ ]* Write test: Endpoints return proper error codes
- [ ]* **✅ PHASE 8 COMPLETE - System Admin endpoints are working**

---

## Phase 9: AdminApi - Role Admin Endpoints

### Task 9.1: Implement POST /api/admin/roles/role-admin endpoint
- [ ] Use `helpers::create_request_context()` to create context
- [ ] Check `ctx.authenticated`, return 401 if false
- [ ] Call `admin_service.assign_role_admin(&ctx, &body.target_user_id)`
- [ ] Convert AdminError to poem::Error
- [ ] Return success response
- [ ] _Requirements: 1.3, 2.1, 6.3, 7.3_
- [ ] _Testable: Endpoint assigns Role Admin role_

### Task 9.2: Implement DELETE /api/admin/roles/role-admin endpoint
- [ ] Use `helpers::create_request_context()` to create context
- [ ] Check `ctx.authenticated`, return 401 if false
- [ ] Call `admin_service.remove_role_admin(&ctx, &body.target_user_id)`
- [ ] Convert AdminError to poem::Error
- [ ] Return success response
- [ ] _Requirements: 1.4, 2.2, 6.4, 7.4_
- [ ] _Testable: Endpoint removes Role Admin role_

### Task 9.3: Test Role Admin endpoints
- [ ]* Write test: POST endpoint assigns Role Admin role
- [ ]* Write test: DELETE endpoint removes Role Admin role
- [ ]* Write test: Owner can use endpoints
- [ ]* Write test: System Admin can use endpoints
- [ ]* Write test: Regular user cannot use endpoints
- [ ]* Write test: Endpoints reject self-modification
- [ ]* Write test: Endpoints return proper error codes
- [ ]* **✅ PHASE 9 COMPLETE - Role Admin endpoints are working**

---

## Phase 10: AdminApi - Owner Deactivation Endpoint

### Task 10.1: Implement POST /api/admin/owner/deactivate endpoint
- [ ] Use `helpers::create_request_context()` to create context
- [ ] Check `ctx.authenticated`, return 401 if false
- [ ] Call `admin_service.deactivate_owner(&ctx)`
- [ ] Convert AdminError to poem::Error
- [ ] Return success response
- [ ] _Requirements: 5.1, 5.2, 5.3_
- [ ] _Testable: Endpoint deactivates owner_

### Task 10.2: Test owner deactivation endpoint
- [ ]* Write test: POST endpoint deactivates owner
- [ ]* Write test: Endpoint requires authentication
- [ ]* Write test: Endpoint requires owner role
- [ ]* Write test: Non-owner cannot use endpoint
- [ ]* Write test: Owner cannot login after deactivation
- [ ]* **✅ PHASE 10 COMPLETE - Owner deactivation endpoint is working**

---

## Phase 11: Integration and Registration

### Task 11.1: Register AdminApi in main.rs
- [ ] Create AdminService instance with all dependencies
- [ ] Create AdminApi instance with admin_service
- [ ] Add AdminApi to OpenApiService tuple
- [ ] Verify server starts successfully
- [ ] _Requirements: All API requirements_
- [ ] _Testable: Server starts and Swagger UI shows admin endpoints_

### Task 11.2: End-to-end integration tests
- [ ]* Write test: Full flow - owner assigns System Admin, System Admin assigns Role Admin
- [ ]* Write test: Token invalidation forces re-authentication with new claims
- [ ]* Write test: Old JWT has stale claims after role change
- [ ]* Write test: Permission boundaries across all endpoints
- [ ]* Write test: All operations logged to audit database
- [ ]* **✅ PHASE 11 COMPLETE - Full integration is working**

---

## Phase 12: Documentation

### Task 12.1: Create API usage documentation
- [ ] Create `docs/admin-role-api.md`
- [ ] Document all admin role management endpoints
- [ ] Document authorization requirements (owner vs system admin)
- [ ] Document error responses and status codes
- [ ] Document owner_active login behavior
- [ ] Include curl examples for each endpoint
- [ ] Document token invalidation behavior
- [ ] _Requirements: All requirements_
- [ ] **✅ PHASE 12 COMPLETE - Documentation is ready**

---

## Testing Checkpoints

After each phase, verify:
- [ ] All tests in that phase pass
- [ ] No regressions in previous phases
- [ ] Code compiles without warnings
- [ ] Audit logs are being written correctly

## Estimated Timeline

- Phase 0: 2-3 hours (CRITICAL - do first)
- Phase 1: 2-3 hours (shared infrastructure)
- Phase 2: 1 hour (token invalidation)
- Phase 3: 1 hour (error types)
- Phase 4: 3-4 hours (System Admin management)
- Phase 5: 2-3 hours (Role Admin management)
- Phase 6: 1-2 hours (Owner deactivation)
- Phase 7: 1 hour (DTOs and structure)
- Phase 8: 2-3 hours (System Admin endpoints)
- Phase 9: 2-3 hours (Role Admin endpoints)
- Phase 10: 1-2 hours (Owner deactivation endpoint)
- Phase 11: 2-3 hours (Integration)
- Phase 12: 1-2 hours (Documentation)

**Total: 21-32 hours**
