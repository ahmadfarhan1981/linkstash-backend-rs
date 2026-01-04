use super::audit_intent::AuditIntent;

pub struct ActionOutcome<T> {
    pub value: T,
    pub audit: Vec<AuditIntent>,
}

impl<T> ActionOutcome<T> {
    pub fn new(value: T) -> Self {
        Self { 
            value, 
            audit: Vec::new() 
        }
    }
}