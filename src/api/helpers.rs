use crate::errors::AuthError;
use crate::providers::TokenProvider;
use crate::types::internal::context::RequestContext;
use poem::Request;
use poem_openapi::auth::{Bearer, BearerAuthorization};
use std::sync::Arc;
