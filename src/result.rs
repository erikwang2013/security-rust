use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttackCategory {
    Injection,
    Protocol,
    Data,
    File,
}

#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub attack_type: String,
    pub category: AttackCategory,
    pub severity: Severity,
    pub matched_pattern: String,
    pub offset: usize,
    pub message: String,
}
