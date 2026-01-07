use std::net::IpAddr;

use poem_openapi::auth::Bearer;

use super::{request_context::RequestContext, request_id::RequestId, request_source::RequestSource};

pub struct RequestContextMeta{
    pub request_id: RequestId,
    pub ip: Option<IpAddr>,
    pub auth: Option<Bearer>,
    pub source: RequestSource,
}

impl From<RequestContextMeta> for RequestContext {
    fn from(_value: RequestContextMeta) -> Self {
        todo!()
    }
}