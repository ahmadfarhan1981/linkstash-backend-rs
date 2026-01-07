use std::{net::IpAddr, sync::Arc};

use poem_openapi::auth::Bearer;

use crate::{
    errors::InternalError,
    providers::{TokenProvider, token_provider},
};

use super::{
    request_context::RequestContext, request_id::RequestId, request_source::RequestSource,
};

pub struct RequestContextMeta {
    pub request_id: RequestId,
    pub ip: Option<IpAddr>,
    pub auth: Option<Bearer>,
    pub source: RequestSource,
}


