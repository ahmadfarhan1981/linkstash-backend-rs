// API layer - HTTP endpoints
pub mod admin;
pub mod auth;
pub mod health;
pub mod helpers;
pub mod user;

pub use admin::AdminApi;
pub use auth::AuthApi;
pub use health::HealthApi;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use migration::token;
use poem::Request;
use poem_openapi::SecurityScheme;
use poem_openapi::auth::{Bearer, BearerAuthorization};
use std::{net::IpAddr, sync::Arc};
use uuid::Uuid;

use crate::config::SecretManager;
use crate::errors::InternalError;
use crate::errors::internal::jwt_validation::JwtValidationError;
use crate::types::internal::auth::Claims;
use crate::{providers::TokenProvider, types::{
    ApiResult,
    internal::context::{RequestContext, RequestContextMeta, RequestId, RequestSource},
}, AppData};

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
        req.remote_addr().as_socket_addr().map(|addr| addr.ip())
    }

    fn generate_request_context_meta(&self, req: &Request) -> RequestContextMeta {
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

    fn generate_request_context(&self, context_meta: RequestContextMeta) -> RequestContext {
        let claims = context_meta
            .auth
            .as_ref()
            .ok_or_else(|| {
                InternalError::Login(crate::errors::internal::login::LoginError::IncorrectPassword)
            })
            .and_then(|bearer| self.token_verifier().validate_jwt(bearer));

        let actor_id = claims
            .as_ref()
            .ok()
            .map(|claims| claims.sub.clone())
            .unwrap_or("unknown".to_owned());

        RequestContext {
            ip_address: context_meta.ip,
            request_id: context_meta.request_id,
            authenticated: claims.is_ok(),
            claims: claims.ok(),
            source: context_meta.source,
            actor_id,
        }
    }

    fn token_verifier(&self) -> Arc<TokenVerifier>;
}

pub struct TokenVerifier {
    secret_manager: Arc<SecretManager>,
}

impl TokenVerifier {
    pub fn new(app_data: Arc<AppData>) -> Self {
        Self{
            secret_manager: Arc::clone(&app_data.secret_manager),
        }
    }
    pub fn validate_jwt(&self, auth: &Bearer) -> Result<Claims, InternalError> {
        let validation = Validation::new(Algorithm::HS256);
        let token = auth.token.as_str();
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret_manager.jwt_secret().as_bytes()),
            &validation,
        )
            .map_err(|e| InternalError::JWTValidation(JwtValidationError::from_error(e, token)));
        // TODO audit intent
        token_data.map(|td| td.claims)
    }
}
