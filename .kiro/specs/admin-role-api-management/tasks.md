# Implementation Plan

**Note:** This spec implements API endpoints for managing admin roles. It depends on the admin-role-system spec being completed first (database schema, JWT claims, store methods).

- [ ] 1. Update AuthService login to check owner_active flag
  - [ ] 1.1 Update AuthService login to check owner_active flag
    - When authenticating user with is_owner=true, check system config owner_active flag
    - Reject login if owner_active=false with appropriate error message
    - Log failed owner login attempts to audit database
    - _Requirements: From admin-role-system spec 3.1, 3.2, 3.3_

- [ ] 2. Error handling for admin API operations
  - [ ] 2.1 Create AdminError enum with all required error types
    - Add OwnerRequired, SystemAdminRequired, OwnerOrSystemAdminRequired variants
    - Add SelfModificationDenied variant
    - Add UserNotFound variant
    - Add OwnerInactive variant (for login rejection)
    - Implement proper HTTP status codes for each error type
    - Implement Display trait for error messages
    - Implement ResponseError trait for poem integration
    - _Requirements: 3.1, 3.2, 3.3, 6.1, 6.2, 6.3, 6.4, 8.1, 8.2, 8.3, 8.4_

- [ ] 3. Service layer for admin API operations
  - [ ] 3.1 Create AdminService struct
    - Add credential_store, system_config_store, token_service, audit_store fields
    - Implement new() constructor
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 2.1, 2.2_
  
  - [ ] 3.2 Implement assign_system_admin method
    - Check authorization (requires is_owner=true)
    - Check for self-modification
    - Call credential_store.set_system_admin()
    - Invalidate user tokens
    - _Requirements: 1.1, 3.1, 3.2, 4.1, 4.2, 4.3, 6.1, 7.1_
  
  - [ ] 3.3 Implement remove_system_admin method
    - Check authorization (requires is_owner=true)
    - Check for self-modification
    - Call credential_store.set_system_admin()
    - Invalidate user tokens
    - _Requirements: 1.2, 3.1, 3.2, 4.1, 4.2, 4.3, 6.1, 7.2_
  
  - [ ] 3.4 Implement assign_role_admin method
    - Check authorization (requires is_owner=true OR is_system_admin=true)
    - Check for self-modification
    - Call credential_store.set_role_admin()
    - Invalidate user tokens
    - _Requirements: 1.3, 2.1, 3.1, 3.2, 4.1, 4.2, 4.3, 6.3, 7.3_
  
  - [ ] 3.5 Implement remove_role_admin method
    - Check authorization (requires is_owner=true OR is_system_admin=true)
    - Check for self-modification
    - Call credential_store.set_role_admin()
    - Invalidate user tokens
    - _Requirements: 1.4, 2.2, 3.1, 3.2, 4.1, 4.2, 4.3, 6.4, 7.4_
  
  - [ ] 3.6 Implement deactivate_owner method
    - Check authorization (requires is_owner=true)
    - Call system_config_store.set_owner_active(false)
    - Invalidate all owner tokens
    - _Requirements: 5.1, 5.2, 5.3, 7.6_
  
  - [ ] 3.7 Implement invalidate_user_tokens helper method
    - Delete all refresh tokens for the specified user
    - _Requirements: 4.1, 4.2_

- [ ] 4. API endpoints for admin operations
  - [ ] 4.1 Create AdminApi struct and DTOs
    - Create src/api/admin.rs
    - Create src/types/dto/admin.rs with request/response types
    - Define AssignRoleRequest, AssignRoleResponse, RemoveRoleRequest, RemoveRoleResponse, DeactivateResponse
    - Add admin_service field to AdminApi
    - _Requirements: All API requirements_
  
  - [ ] 4.2 Implement POST /admin/roles/system-admin endpoint
    - Create RequestContext and check authentication
    - Call admin_service.assign_system_admin()
    - Return success response
    - _Requirements: 1.1, 6.1, 7.1_
  
  - [ ] 4.3 Implement DELETE /admin/roles/system-admin endpoint
    - Create RequestContext and check authentication
    - Call admin_service.remove_system_admin()
    - Return success response
    - _Requirements: 1.2, 6.1, 7.2_
  
  - [ ] 4.4 Implement POST /admin/roles/role-admin endpoint
    - Create RequestContext and check authentication
    - Call admin_service.assign_role_admin()
    - Return success response
    - _Requirements: 1.3, 2.1, 6.3, 7.3_
  
  - [ ] 4.5 Implement DELETE /admin/roles/role-admin endpoint
    - Create RequestContext and check authentication
    - Call admin_service.remove_role_admin()
    - Return success response
    - _Requirements: 1.4, 2.2, 6.4, 7.4_
  
  - [ ] 4.6 Implement POST /admin/owner/deactivate endpoint
    - Create RequestContext and check authentication
    - Call admin_service.deactivate_owner()
    - Return success response
    - _Requirements: 5.1, 5.2, 5.3_
  
  - [ ] 4.7 Register AdminApi in main.rs
    - Add AdminApi to OpenApiService
    - Wire up AdminService dependency
    - _Requirements: All API requirements_

- [ ] 5. Audit logging for API operations
  - [ ] 5.1 Extend audit event types for API operations
    - Add event types for admin role assignments/removals via API
    - Add event types for self-modification attempts
    - Add event types for owner deactivation via API
    - Add event types for owner login rejection (owner_active=false)
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6_
  
  - [ ] 5.2 Verify audit logger captures API operation metadata
    - Ensure actor_user_id and target_user_id are captured
    - Ensure roles_modified field captures changed roles
    - Ensure IP address is captured from RequestContext
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6_

- [ ]* 6. Testing
  - [ ]* 6.1 Write unit tests for owner_active login check
    - Test owner with owner_active=false cannot login
    - Test owner with owner_active=true can login
    - Test failed owner login attempts are logged
    - _Requirements: From admin-role-system spec 3.1, 3.2, 3.3_
  
  - [ ]* 6.2 Write unit tests for authorization logic
    - Test owner can assign/remove System Admin and Role Admin
    - Test System Admin can assign/remove Role Admin only
    - Test non-admins cannot perform admin operations
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 2.1, 2.2, 6.1, 6.2, 6.3, 6.4_
  
  - [ ]* 6.3 Write unit tests for self-modification checks
    - Test rejection of admin role self-assignment
    - Test rejection of admin role self-removal
    - _Requirements: 3.1, 3.2_
  
  - [ ]* 6.4 Write integration tests for role assignment flow
    - Test owner assigns System Admin via API and verify database updated
    - Test System Admin assigns Role Admin via API and verify database updated
    - Test tokens invalidated after role changes
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 4.1, 4.2, 4.3_
  
  - [ ]* 6.5 Write integration tests for permission boundaries
    - Test System Admin cannot assign System Admin (only Owner can)
    - Test non-admin cannot assign any roles
    - _Requirements: 6.1, 6.2, 6.3, 6.4_
  
  - [ ]* 6.6 Write integration tests for audit logging
    - Test all role changes logged with correct metadata
    - Test self-modification attempts logged
    - Test owner deactivation logged
    - Test owner login rejection logged
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6_

- [ ] 7. Documentation
  - [ ] 7.1 Create API usage documentation
    - Document admin role management API endpoints
    - Document authorization requirements
    - Document error responses
    - Document owner_active login behavior
    - Add to docs/ directory
    - _Requirements: All requirements_
