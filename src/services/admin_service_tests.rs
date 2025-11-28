#[cfg(test)]
mod tests {
    use super::super::AdminService;
    use crate::app_data::AppData;
    use crate::types::internal::context::RequestContext;
    use crate::types::internal::auth::{AdminFlags, Claims};
    use crate::errors::admin::AdminError;
    use crate::test::utils::setup_test_stores;
    use std::sync::Arc;
    use uuid::Uuid;

    /// Helper to create AppData for testing
    async fn setup_app_data() -> Arc<AppData> {
        let (db, audit_db, credential_store, audit_store) = setup_test_stores().await;
        
        // Create system_config_store
        let system_config_store = Arc::new(crate::stores::SystemConfigStore::new(
            db.clone(),
            audit_store.clone(),
        ));
        
        // Create token_service
        let token_service = Arc::new(crate::services::TokenService::new(
            "test_jwt_secret_at_least_32_chars_long".to_string(),
            "test_refresh_secret_at_least_32_chars".to_string(),
            audit_store.clone(),
        ));
        
        // Set environment variables for SecretManager::init()
        unsafe {
            std::env::set_var("JWT_SECRET", "test-secret-key-minimum-32-characters-long");
            std::env::set_var("PASSWORD_PEPPER", "test-pepper-for-unit-tests");
            std::env::set_var("REFRESH_TOKEN_SECRET", "test-refresh-secret-minimum-32-chars");
        }
        
        let secret_manager = Arc::new(crate::config::SecretManager::init()
            .expect("Failed to initialize test SecretManager"));
        
        Arc::new(AppData {
            db,
            audit_db,
            secret_manager,
            audit_store,
            credential_store,
            system_config_store,
            token_service,
        })
    }

    /// Helper to create a test user with specific admin flags
    async fn create_test_user(
        app_data: &Arc<AppData>,
        username: &str,
        admin_flags: AdminFlags,
    ) -> String {
        let ctx = RequestContext::new();
        let password_hash = "$argon2id$v=19$m=19456,t=2,p=1$test$testhash".to_string();
        
        let user_id = app_data.credential_store
            .create_user(&ctx, username.to_string(), password_hash)
            .await
            .unwrap();
        
        if admin_flags.is_owner || admin_flags.is_system_admin || admin_flags.is_role_admin {
            app_data.credential_store
                .set_privileges(&ctx, &user_id, admin_flags)
                .await
                .unwrap();
        }
        
        user_id
    }

    /// Helper to create a RequestContext with specific claims
    fn create_context_with_claims(user_id: &str, is_owner: bool, is_system_admin: bool, is_role_admin: bool) -> RequestContext {
        let claims = Claims {
            sub: user_id.to_string(),
            exp: 9999999999,
            iat: 0,
            jti: Some(Uuid::new_v4().to_string()),
            is_owner,
            is_system_admin,
            is_role_admin,
            app_roles: vec![],
        };
        
        RequestContext::new()
            .with_ip_address("127.0.0.1".to_string())
            .with_auth(claims)
    }

    // ==================== Test Group 1: assign_system_admin() ====================
    
    mod assign_system_admin_tests {
        use super::*;

        #[tokio::test]
        async fn owner_can_assign_system_admin() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let owner_id = create_test_user(&app_data, "owner", AdminFlags {
                is_owner: true,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            let target_id = create_test_user(&app_data, "target", AdminFlags {
                is_owner: false,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            let ctx = create_context_with_claims(&owner_id, true, false, false);
            
            let result = service.assign_system_admin(&ctx, &target_id).await;
            assert!(result.is_ok());
            
            // Verify database was updated
            let user = app_data.credential_store.get_user_by_id(&target_id).await.unwrap();
            assert!(user.is_system_admin);
        }

        #[tokio::test]
        async fn system_admin_cannot_assign_system_admin() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let admin_id = create_test_user(&app_data, "admin", AdminFlags {
                is_owner: false,
                is_system_admin: true,
                is_role_admin: false,
            }).await;
            
            let target_id = create_test_user(&app_data, "target", AdminFlags {
                is_owner: false,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            let ctx = create_context_with_claims(&admin_id, false, true, false);
            
            let result = service.assign_system_admin(&ctx, &target_id).await;
            assert!(matches!(result, Err(AdminError::OwnerRequired(_))));
        }

        #[tokio::test]
        async fn regular_user_cannot_assign_system_admin() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let user_id = create_test_user(&app_data, "user", AdminFlags {
                is_owner: false,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            let target_id = create_test_user(&app_data, "target", AdminFlags {
                is_owner: false,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            let ctx = create_context_with_claims(&user_id, false, false, false);
            
            let result = service.assign_system_admin(&ctx, &target_id).await;
            assert!(matches!(result, Err(AdminError::OwnerRequired(_))));
        }

        #[tokio::test]
        async fn unauthenticated_request_fails() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let target_id = create_test_user(&app_data, "target", AdminFlags {
                is_owner: false,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            let ctx = RequestContext::new(); // No claims
            
            let result = service.assign_system_admin(&ctx, &target_id).await;
            assert!(matches!(result, Err(AdminError::InternalError(_))));
        }

        #[tokio::test]
        async fn owner_cannot_assign_system_admin_to_themselves() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let owner_id = create_test_user(&app_data, "owner", AdminFlags {
                is_owner: true,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            let ctx = create_context_with_claims(&owner_id, true, false, false);
            
            let result = service.assign_system_admin(&ctx, &owner_id).await;
            assert!(matches!(result, Err(AdminError::SelfModificationDenied(_))));
        }

        #[tokio::test]
        async fn assignment_preserves_other_flags() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let owner_id = create_test_user(&app_data, "owner", AdminFlags {
                is_owner: true,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            let target_id = create_test_user(&app_data, "target", AdminFlags {
                is_owner: false,
                is_system_admin: false,
                is_role_admin: true, // Has role_admin
            }).await;
            
            let ctx = create_context_with_claims(&owner_id, true, false, false);
            
            service.assign_system_admin(&ctx, &target_id).await.unwrap();
            
            let user = app_data.credential_store.get_user_by_id(&target_id).await.unwrap();
            assert!(user.is_system_admin); // New flag set
            assert!(user.is_role_admin);   // Old flag preserved
            assert!(!user.is_owner);       // Other flag unchanged
        }

        #[tokio::test]
        async fn assignment_updates_database() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let owner_id = create_test_user(&app_data, "owner", AdminFlags {
                is_owner: true,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            let target_id = create_test_user(&app_data, "target", AdminFlags {
                is_owner: false,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            let ctx = create_context_with_claims(&owner_id, true, false, false);
            
            service.assign_system_admin(&ctx, &target_id).await.unwrap();
            
            let user = app_data.credential_store.get_user_by_id(&target_id).await.unwrap();
            assert_eq!(user.is_system_admin, true);
        }

        #[tokio::test]
        async fn assignment_fails_for_nonexistent_user() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let owner_id = create_test_user(&app_data, "owner", AdminFlags {
                is_owner: true,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            let ctx = create_context_with_claims(&owner_id, true, false, false);
            let fake_user_id = Uuid::new_v4().to_string();
            
            let result = service.assign_system_admin(&ctx, &fake_user_id).await;
            assert!(matches!(result, Err(AdminError::UserNotFound(_))));
        }
    }

    // ==================== Test Group 2: remove_system_admin() ====================
    
    mod remove_system_admin_tests {
        use super::*;

        #[tokio::test]
        async fn owner_can_remove_system_admin() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let owner_id = create_test_user(&app_data, "owner", AdminFlags {
                is_owner: true,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            let target_id = create_test_user(&app_data, "target", AdminFlags {
                is_owner: false,
                is_system_admin: true,
                is_role_admin: false,
            }).await;
            
            let ctx = create_context_with_claims(&owner_id, true, false, false);
            
            let result = service.remove_system_admin(&ctx, &target_id).await;
            assert!(result.is_ok());
            
            let user = app_data.credential_store.get_user_by_id(&target_id).await.unwrap();
            assert!(!user.is_system_admin);
        }

        #[tokio::test]
        async fn system_admin_cannot_remove_system_admin() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let admin_id = create_test_user(&app_data, "admin", AdminFlags {
                is_owner: false,
                is_system_admin: true,
                is_role_admin: false,
            }).await;
            
            let target_id = create_test_user(&app_data, "target", AdminFlags {
                is_owner: false,
                is_system_admin: true,
                is_role_admin: false,
            }).await;
            
            let ctx = create_context_with_claims(&admin_id, false, true, false);
            
            let result = service.remove_system_admin(&ctx, &target_id).await;
            assert!(matches!(result, Err(AdminError::OwnerRequired(_))));
        }

        #[tokio::test]
        async fn regular_user_cannot_remove_system_admin() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let user_id = create_test_user(&app_data, "user", AdminFlags {
                is_owner: false,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            let target_id = create_test_user(&app_data, "target", AdminFlags {
                is_owner: false,
                is_system_admin: true,
                is_role_admin: false,
            }).await;
            
            let ctx = create_context_with_claims(&user_id, false, false, false);
            
            let result = service.remove_system_admin(&ctx, &target_id).await;
            assert!(matches!(result, Err(AdminError::OwnerRequired(_))));
        }

        #[tokio::test]
        async fn owner_cannot_remove_system_admin_from_themselves() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let owner_id = create_test_user(&app_data, "owner", AdminFlags {
                is_owner: true,
                is_system_admin: true,
                is_role_admin: false,
            }).await;
            
            let ctx = create_context_with_claims(&owner_id, true, true, false);
            
            let result = service.remove_system_admin(&ctx, &owner_id).await;
            assert!(matches!(result, Err(AdminError::SelfModificationDenied(_))));
        }

        #[tokio::test]
        async fn removal_preserves_other_flags() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let owner_id = create_test_user(&app_data, "owner", AdminFlags {
                is_owner: true,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            let target_id = create_test_user(&app_data, "target", AdminFlags {
                is_owner: false,
                is_system_admin: true,
                is_role_admin: true,
            }).await;
            
            let ctx = create_context_with_claims(&owner_id, true, false, false);
            
            service.remove_system_admin(&ctx, &target_id).await.unwrap();
            
            let user = app_data.credential_store.get_user_by_id(&target_id).await.unwrap();
            assert!(!user.is_system_admin); // Flag removed
            assert!(user.is_role_admin);    // Other flag preserved
        }

        #[tokio::test]
        async fn removal_updates_database() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let owner_id = create_test_user(&app_data, "owner", AdminFlags {
                is_owner: true,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            let target_id = create_test_user(&app_data, "target", AdminFlags {
                is_owner: false,
                is_system_admin: true,
                is_role_admin: false,
            }).await;
            
            let ctx = create_context_with_claims(&owner_id, true, false, false);
            
            service.remove_system_admin(&ctx, &target_id).await.unwrap();
            
            let user = app_data.credential_store.get_user_by_id(&target_id).await.unwrap();
            assert_eq!(user.is_system_admin, false);
        }
    }

    // ==================== Test Group 3: assign_role_admin() ====================
    
    mod assign_role_admin_tests {
        use super::*;

        #[tokio::test]
        async fn owner_can_assign_role_admin() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let owner_id = create_test_user(&app_data, "owner", AdminFlags {
                is_owner: true,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            let target_id = create_test_user(&app_data, "target", AdminFlags {
                is_owner: false,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            let ctx = create_context_with_claims(&owner_id, true, false, false);
            
            let result = service.assign_role_admin(&ctx, &target_id).await;
            assert!(result.is_ok());
            
            let user = app_data.credential_store.get_user_by_id(&target_id).await.unwrap();
            assert!(user.is_role_admin);
        }

        #[tokio::test]
        async fn system_admin_can_assign_role_admin() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let admin_id = create_test_user(&app_data, "admin", AdminFlags {
                is_owner: false,
                is_system_admin: true,
                is_role_admin: false,
            }).await;
            
            let target_id = create_test_user(&app_data, "target", AdminFlags {
                is_owner: false,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            let ctx = create_context_with_claims(&admin_id, false, true, false);
            
            let result = service.assign_role_admin(&ctx, &target_id).await;
            assert!(result.is_ok());
            
            let user = app_data.credential_store.get_user_by_id(&target_id).await.unwrap();
            assert!(user.is_role_admin);
        }

        #[tokio::test]
        async fn regular_user_cannot_assign_role_admin() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let user_id = create_test_user(&app_data, "user", AdminFlags {
                is_owner: false,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            let target_id = create_test_user(&app_data, "target", AdminFlags {
                is_owner: false,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            let ctx = create_context_with_claims(&user_id, false, false, false);
            
            let result = service.assign_role_admin(&ctx, &target_id).await;
            assert!(matches!(result, Err(AdminError::OwnerOrSystemAdminRequired(_))));
        }

        #[tokio::test]
        async fn owner_cannot_assign_role_admin_to_themselves() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let owner_id = create_test_user(&app_data, "owner", AdminFlags {
                is_owner: true,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            let ctx = create_context_with_claims(&owner_id, true, false, false);
            
            let result = service.assign_role_admin(&ctx, &owner_id).await;
            assert!(matches!(result, Err(AdminError::SelfModificationDenied(_))));
        }

        #[tokio::test]
        async fn system_admin_cannot_assign_role_admin_to_themselves() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let admin_id = create_test_user(&app_data, "admin", AdminFlags {
                is_owner: false,
                is_system_admin: true,
                is_role_admin: false,
            }).await;
            
            let ctx = create_context_with_claims(&admin_id, false, true, false);
            
            let result = service.assign_role_admin(&ctx, &admin_id).await;
            assert!(matches!(result, Err(AdminError::SelfModificationDenied(_))));
        }

        #[tokio::test]
        async fn assignment_preserves_other_flags() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let owner_id = create_test_user(&app_data, "owner", AdminFlags {
                is_owner: true,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            let target_id = create_test_user(&app_data, "target", AdminFlags {
                is_owner: false,
                is_system_admin: true,
                is_role_admin: false,
            }).await;
            
            let ctx = create_context_with_claims(&owner_id, true, false, false);
            
            service.assign_role_admin(&ctx, &target_id).await.unwrap();
            
            let user = app_data.credential_store.get_user_by_id(&target_id).await.unwrap();
            assert!(user.is_role_admin);    // New flag set
            assert!(user.is_system_admin);  // Old flag preserved
        }

        #[tokio::test]
        async fn assignment_updates_database() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let owner_id = create_test_user(&app_data, "owner", AdminFlags {
                is_owner: true,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            let target_id = create_test_user(&app_data, "target", AdminFlags {
                is_owner: false,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            let ctx = create_context_with_claims(&owner_id, true, false, false);
            
            service.assign_role_admin(&ctx, &target_id).await.unwrap();
            
            let user = app_data.credential_store.get_user_by_id(&target_id).await.unwrap();
            assert_eq!(user.is_role_admin, true);
        }
    }

    // ==================== Test Group 4: remove_role_admin() ====================
    
    mod remove_role_admin_tests {
        use super::*;

        #[tokio::test]
        async fn owner_can_remove_role_admin() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let owner_id = create_test_user(&app_data, "owner", AdminFlags {
                is_owner: true,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            let target_id = create_test_user(&app_data, "target", AdminFlags {
                is_owner: false,
                is_system_admin: false,
                is_role_admin: true,
            }).await;
            
            let ctx = create_context_with_claims(&owner_id, true, false, false);
            
            let result = service.remove_role_admin(&ctx, &target_id).await;
            assert!(result.is_ok());
            
            let user = app_data.credential_store.get_user_by_id(&target_id).await.unwrap();
            assert!(!user.is_role_admin);
        }

        #[tokio::test]
        async fn system_admin_can_remove_role_admin() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let admin_id = create_test_user(&app_data, "admin", AdminFlags {
                is_owner: false,
                is_system_admin: true,
                is_role_admin: false,
            }).await;
            
            let target_id = create_test_user(&app_data, "target", AdminFlags {
                is_owner: false,
                is_system_admin: false,
                is_role_admin: true,
            }).await;
            
            let ctx = create_context_with_claims(&admin_id, false, true, false);
            
            let result = service.remove_role_admin(&ctx, &target_id).await;
            assert!(result.is_ok());
            
            let user = app_data.credential_store.get_user_by_id(&target_id).await.unwrap();
            assert!(!user.is_role_admin);
        }

        #[tokio::test]
        async fn regular_user_cannot_remove_role_admin() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let user_id = create_test_user(&app_data, "user", AdminFlags {
                is_owner: false,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            let target_id = create_test_user(&app_data, "target", AdminFlags {
                is_owner: false,
                is_system_admin: false,
                is_role_admin: true,
            }).await;
            
            let ctx = create_context_with_claims(&user_id, false, false, false);
            
            let result = service.remove_role_admin(&ctx, &target_id).await;
            assert!(matches!(result, Err(AdminError::OwnerOrSystemAdminRequired(_))));
        }

        #[tokio::test]
        async fn system_admin_cannot_remove_role_admin_from_themselves() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let admin_id = create_test_user(&app_data, "admin", AdminFlags {
                is_owner: false,
                is_system_admin: true,
                is_role_admin: true,
            }).await;
            
            let ctx = create_context_with_claims(&admin_id, false, true, true);
            
            let result = service.remove_role_admin(&ctx, &admin_id).await;
            assert!(matches!(result, Err(AdminError::SelfModificationDenied(_))));
        }

        #[tokio::test]
        async fn removal_preserves_other_flags() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let owner_id = create_test_user(&app_data, "owner", AdminFlags {
                is_owner: true,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            let target_id = create_test_user(&app_data, "target", AdminFlags {
                is_owner: false,
                is_system_admin: true,
                is_role_admin: true,
            }).await;
            
            let ctx = create_context_with_claims(&owner_id, true, false, false);
            
            service.remove_role_admin(&ctx, &target_id).await.unwrap();
            
            let user = app_data.credential_store.get_user_by_id(&target_id).await.unwrap();
            assert!(!user.is_role_admin);   // Flag removed
            assert!(user.is_system_admin);  // Other flag preserved
        }

        #[tokio::test]
        async fn removal_updates_database() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let owner_id = create_test_user(&app_data, "owner", AdminFlags {
                is_owner: true,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            let target_id = create_test_user(&app_data, "target", AdminFlags {
                is_owner: false,
                is_system_admin: false,
                is_role_admin: true,
            }).await;
            
            let ctx = create_context_with_claims(&owner_id, true, false, false);
            
            service.remove_role_admin(&ctx, &target_id).await.unwrap();
            
            let user = app_data.credential_store.get_user_by_id(&target_id).await.unwrap();
            assert_eq!(user.is_role_admin, false);
        }
    }

    // ==================== Test Group 5: deactivate_owner() ====================
    
    mod deactivate_owner_tests {
        use super::*;

        #[tokio::test]
        async fn owner_can_deactivate_themselves() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let owner_id = create_test_user(&app_data, "owner", AdminFlags {
                is_owner: true,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            // Activate owner first
            app_data.system_config_store
                .set_owner_active(true, Some(owner_id.clone()), Some("127.0.0.1".to_string()))
                .await
                .unwrap();
            
            let ctx = create_context_with_claims(&owner_id, true, false, false);
            
            let result = service.deactivate_owner(&ctx).await;
            assert!(result.is_ok());
            
            // Verify owner_active is false
            let is_active = app_data.system_config_store.is_owner_active().await.unwrap();
            assert!(!is_active);
        }

        #[tokio::test]
        async fn system_admin_cannot_deactivate_owner() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let admin_id = create_test_user(&app_data, "admin", AdminFlags {
                is_owner: false,
                is_system_admin: true,
                is_role_admin: false,
            }).await;
            
            let ctx = create_context_with_claims(&admin_id, false, true, false);
            
            let result = service.deactivate_owner(&ctx).await;
            assert!(matches!(result, Err(AdminError::OwnerRequired(_))));
        }

        #[tokio::test]
        async fn regular_user_cannot_deactivate_owner() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let user_id = create_test_user(&app_data, "user", AdminFlags {
                is_owner: false,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            let ctx = create_context_with_claims(&user_id, false, false, false);
            
            let result = service.deactivate_owner(&ctx).await;
            assert!(matches!(result, Err(AdminError::OwnerRequired(_))));
        }

        #[tokio::test]
        async fn deactivation_sets_owner_active_false() {
            let app_data = setup_app_data().await;
            let service = AdminService::new(app_data.clone());
            
            let owner_id = create_test_user(&app_data, "owner", AdminFlags {
                is_owner: true,
                is_system_admin: false,
                is_role_admin: false,
            }).await;
            
            // Activate owner first
            app_data.system_config_store
                .set_owner_active(true, Some(owner_id.clone()), Some("127.0.0.1".to_string()))
                .await
                .unwrap();
            
            let ctx = create_context_with_claims(&owner_id, true, false, false);
            
            service.deactivate_owner(&ctx).await.unwrap();
            
            let config = app_data.system_config_store.get_config().await.unwrap();
            assert_eq!(config.owner_active, false);
        }
    }
}
