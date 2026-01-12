// API layer - HTTP endpoints
pub mod admin;
pub mod auth;
pub mod health;
pub mod helpers;
pub mod user;

use std::{net::IpAddr, sync::Arc};

pub use admin::AdminApi;
pub use auth::AuthApi;
pub use health::HealthApi;
use migration::token;
use poem::Request;
use poem_openapi::auth::{Bearer, BearerAuthorization};
use poem_openapi::SecurityScheme;
use uuid::Uuid;


use crate::{providers::TokenProvider, types::{ApiResult, internal::context::{RequestContext, RequestContextMeta, RequestId, RequestSource}}};

/// JWT Bearer token authentication
#[derive(SecurityScheme, Debug)]
#[oai(
    ty = "bearer",
    key_name = "Authorization",
    key_in = "header",
    bearer_format = "JWT"
)]
pub struct BearerAuth(pub Bearer);

pub trait Api {
   
    fn extract_ip_address(&self, req: &Request) -> Option<IpAddr> {
        // Check X-Forwarded-For header (proxy/load balancer)
        if let Some(forwarded) = req.header("X-Forwarded-For") {
            if let Some(ip) = forwarded.split(',').next() {
                return ip.trim().parse().ok();
            }
        }

        // Check X-Real-IP header (nginx)
        if let Some(real_ip) = req.header("X-Real-IP") {
            return real_ip.parse().ok();
        }

        // Fall back to remote address
        req.remote_addr()
            .as_socket_addr()
            .map(|addr| addr.ip())
    }

    fn generate_request_context_meta(&self, req: &Request)->RequestContextMeta{
        let ip = self.extract_ip_address(req);
        let auth = match Bearer::from_request(req) {
            Ok(bearer) => Some(bearer),
            Err(_) => None,
        };
        let request_id = RequestId(Uuid::new_v4());
        
        RequestContextMeta {
            request_id,
            ip,
            auth,
            source: RequestSource::API,
        }
    }

    fn verify_token(&self){

    }
}

