// API layer - HTTP endpoints
pub mod admin;
pub mod auth;
pub mod health;
pub mod helpers;

use std::{net::IpAddr, sync::Arc};

pub use admin::AdminApi;
pub use auth::AuthApi;
pub use health::HealthApi;
use migration::token;
use poem::Request;
use poem_openapi::auth::Bearer;


use crate::{providers::TokenProvider, types::{ApiResult, internal::context::RequestContext}};


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
}

