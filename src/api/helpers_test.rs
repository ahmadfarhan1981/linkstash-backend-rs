#[cfg(test)]
mod tests {
    use crate::api::helpers::*;
    use poem::Request;
    use poem_openapi::auth::Bearer;
    use crate::test::utils::setup_test_auth_services;

    #[test]
    fn test_extract_ip_from_x_forwarded_for() {
        let req = Request::builder()
            .header("X-Forwarded-For", "192.168.1.1, 10.0.0.1")
            .finish();
        
        let ip = extract_ip_address(&req);
        assert_eq!(ip, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn test_extract_ip_from_x_real_ip() {
        let req = Request::builder()
            .header("X-Real-IP", "192.168.1.2")
            .finish();
        
        let ip = extract_ip_address(&req);
        assert_eq!(ip, Some("192.168.1.2".to_string()));
    }

    #[test]
    fn test_extract_ip_fallback_to_remote_addr() {
        // When no headers are present, remote_addr returns None in test
        let req = Request::builder().finish();
        
        let ip = extract_ip_address(&req);
        // In test environment, remote_addr is None
        assert_eq!(ip, None);
    }

    #[tokio::test]
    async fn test_create_request_context_with_valid_jwt() {
        let (_db, _audit_db, _credential_store, _audit_store, _auth_service, token_service) = 
            setup_test_auth_services().await;
        
        // Generate a valid JWT
        let user_id = uuid::Uuid::new_v4();
        let ctx = crate::types::internal::context::RequestContext::new()
            .with_ip_address("127.0.0.1");
        let (jwt, _jwt_id) = token_service.generate_jwt(
            &ctx,
            &user_id,
            false,
            false,
            false,
            vec![],
        ).await.unwrap();
        
        let req = Request::builder().finish();
        let bearer = Bearer { token: jwt };
        
        let ctx = create_request_context(&req, Some(bearer), &token_service).await;
        
        assert!(ctx.authenticated);
        assert!(ctx.claims.is_some());
        assert_eq!(ctx.claims.unwrap().sub, user_id.to_string());
    }

    #[tokio::test]
    async fn test_create_request_context_with_invalid_jwt() {
        let (_db, _audit_db, _credential_store, _audit_store, _auth_service, token_service) = 
            setup_test_auth_services().await;
        
        let req = Request::builder().finish();
        let bearer = Bearer { token: "invalid-jwt-token".to_string() };
        
        let ctx = create_request_context(&req, Some(bearer), &token_service).await;
        
        assert!(!ctx.authenticated);
        assert!(ctx.claims.is_none());
    }

    #[tokio::test]
    async fn test_create_request_context_without_auth() {
        let (_db, _audit_db, _credential_store, _audit_store, _auth_service, token_service) = 
            setup_test_auth_services().await;
        
        let req = Request::builder().finish();
        
        let ctx = create_request_context(&req, None, &token_service).await;
        
        assert!(!ctx.authenticated);
        assert!(ctx.claims.is_none());
        assert_eq!(ctx.actor_id, "unknown");
    }
}
