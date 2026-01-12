use std::sync::Arc;
use sea_orm::ConnectionTrait;

use crate::providers::{CryptoProvider, TokenProvider};
use crate::stores::authentication_store::AuthenticationStore;
use crate::stores::user_store::UserStore;
use crate::types::{ProviderResult, ProviderResultTrait};

pub struct UserProvider {
    user_store: Arc<UserStore>
}

impl UserProvider {
     pub fn new(user_store:Arc<UserStore>) -> Self {
         Self { user_store }
     }
    

    pub async fn user_exists(&self, conn:&impl ConnectionTrait, username: &str)->ProviderResult<bool>{

        let result = self.user_store.username_in_use(conn, username).await?;

        ProviderResult::new(result.value)
    }
    
    
}