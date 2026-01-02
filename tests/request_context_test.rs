use linkstash_backend::types::internal::context::{RequestContext, RequestSource};

#[test]
fn test_request_context_new_defaults_to_api_source() {
    let ctx = RequestContext::new();

    assert_eq!(ctx.source, RequestSource::API);
    assert_eq!(ctx.actor_id, "unknown");
    assert!(!ctx.authenticated);
    assert!(ctx.claims.is_none());
}

#[test]
fn test_request_context_for_cli() {
    let ctx = RequestContext::for_cli("bootstrap");

    assert_eq!(ctx.source, RequestSource::CLI);
    assert_eq!(ctx.actor_id, "cli:bootstrap");
    assert_eq!(ctx.ip_address, Some("localhost".to_string()));
    assert!(!ctx.authenticated);
    assert!(ctx.claims.is_none());
}

#[test]
fn test_request_context_for_system() {
    let ctx = RequestContext::for_system("cleanup");

    assert_eq!(ctx.source, RequestSource::System);
    assert_eq!(ctx.actor_id, "system:cleanup");
    assert!(ctx.ip_address.is_none());
    assert!(!ctx.authenticated);
    assert!(ctx.claims.is_none());
}

#[test]
fn test_request_context_with_ip_address() {
    let ctx = RequestContext::new().with_ip_address("192.168.1.1");

    assert_eq!(ctx.ip_address, Some("192.168.1.1".to_string()));
    assert_eq!(ctx.source, RequestSource::API);
}
