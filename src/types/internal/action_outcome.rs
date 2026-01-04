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

    /// Add a single audit intent to the outcome
    pub fn with_audit(mut self, audit_intent: AuditIntent) -> Self {
        self.audit.push(audit_intent);
        self
    }

    /// Add multiple audit intents to the outcome
    pub fn with_audits(mut self, audit_intents: Vec<AuditIntent>) -> Self {
        self.audit.extend(audit_intents);
        self
    }

}