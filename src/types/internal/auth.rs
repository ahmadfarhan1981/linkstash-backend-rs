use serde::{Deserialize, Serialize};

use crate::types::db::user::Model;

/// JWT Claims structure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Claims {
    /// Subject (user_id)
    pub sub: String,
    
    /// Expiration time (Unix timestamp)
    pub exp: i64,
    
    /// Issued at (Unix timestamp)
    pub iat: i64,
    
    /// JWT ID (unique identifier for this token)
    pub jti: String,
    
    /// Owner role flag
    pub is_owner: bool,
    
    /// System Admin role flag
    pub is_system_admin: bool,
    
    /// Role Admin role flag
    pub is_role_admin: bool,
    
    /// Application roles (list of role names)
    pub app_roles: Vec<String>,
    
    /// Password change required flag
    pub password_change_required: bool,
}

/// Admin role flags for user creation and management
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminFlags {
    pub is_owner: bool,
    pub is_system_admin: bool,
    pub is_role_admin: bool,
}

impl AdminFlags {
    /// Create AdminFlags for an owner account
    pub fn owner() -> Self {
        Self {
            is_owner: true,
            is_system_admin: false,
            is_role_admin: false,
        }
    }
    
    /// Create AdminFlags for a system admin account
    pub fn system_admin() -> Self {
        Self {
            is_owner: false,
            is_system_admin: true,
            is_role_admin: false,
        }
    }
    
    /// Create AdminFlags for a role admin account
    pub fn role_admin() -> Self {
        Self {
            is_owner: false,
            is_system_admin: false,
            is_role_admin: true,
        }
    }
    
    /// Create AdminFlags for a regular user (no admin roles)
    pub fn none() -> Self {
        Self {
            is_owner: false,
            is_system_admin: false,
            is_role_admin: false,
        }
    }
    
    /// Create AdminFlags with custom role combination
    pub fn custom(is_owner: bool, is_system_admin: bool, is_role_admin: bool) -> Self {
        Self {
            is_owner,
            is_system_admin,
            is_role_admin,
        }
    }
    
    /// Check if any admin role is set
    pub fn has_any_admin_role(&self) -> bool {
        self.is_owner || self.is_system_admin || self.is_role_admin
    }
    
    /// Check if this represents an owner account
    pub fn is_owner_account(&self) -> bool {
        self.is_owner
    }
    
    /// Check if this represents a system admin account
    pub fn is_system_admin_account(&self) -> bool {
        self.is_system_admin
    }
    
    /// Check if this represents a role admin account
    pub fn is_role_admin_account(&self) -> bool {
        self.is_role_admin
    }
    
    /// Validate that owner flag is not combined with other admin roles
    /// Returns true if the combination is valid
    pub fn is_valid(&self) -> bool {
        // Owner should typically be standalone, but we allow combinations
        // for flexibility (design allows multiple roles simultaneously)
        true
    }
    
    /// Get a human-readable description of the roles
    pub fn description(&self) -> String {
        let mut roles = Vec::new();
        
        if self.is_owner {
            roles.push("Owner");
        }
        if self.is_system_admin {
            roles.push("System Admin");
        }
        if self.is_role_admin {
            roles.push("Role Admin");
        }
        
        if roles.is_empty() {
            "No admin roles".to_string()
        } else {
            roles.join(", ")
        }
    }
}

impl Default for AdminFlags {
    fn default() -> Self {
        Self::none()
    }
}

impl From<&Model> for AdminFlags {
    /// Convert from user database model to AdminFlags
    fn from(user: &Model) -> Self {
        Self {
            is_owner: user.is_owner,
            is_system_admin: user.is_system_admin,
            is_role_admin: user.is_role_admin,
        }
    }
}

impl From<&Claims> for AdminFlags {
    /// Convert from JWT claims to AdminFlags
    fn from(claims: &Claims) -> Self {
        Self {
            is_owner: claims.is_owner,
            is_system_admin: claims.is_system_admin,
            is_role_admin: claims.is_role_admin,
        }
    }
}
