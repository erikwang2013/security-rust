// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionResult {
    pub attack_type: String,
    pub category: AttackCategory,
    pub severity: Severity,
    pub matched_pattern: String,
    pub offset: usize,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> DetectionResult {
        DetectionResult {
            attack_type: "xss".into(),
            category: AttackCategory::Injection,
            severity: Severity::Critical,
            matched_pattern: "<script>".into(),
            offset: 0,
            message: "XSS detected".into(),
        }
    }

    #[test]
    fn severity_display_uppercase() {
        assert_eq!(Severity::Critical.to_string(), "CRITICAL");
        assert_eq!(Severity::High.to_string(), "HIGH");
        assert_eq!(Severity::Medium.to_string(), "MEDIUM");
        assert_eq!(Severity::Low.to_string(), "LOW");
    }

    #[test]
    fn severity_equality() {
        assert_eq!(Severity::Critical, Severity::Critical);
        assert_ne!(Severity::Critical, Severity::High);
        assert_ne!(Severity::Medium, Severity::Low);
    }

    #[test]
    fn attack_category_equality() {
        assert_eq!(AttackCategory::Injection, AttackCategory::Injection);
        assert_ne!(AttackCategory::Injection, AttackCategory::Protocol);
        assert_ne!(AttackCategory::Data, AttackCategory::File);
    }

    #[test]
    fn detection_result_clone_and_equality() {
        let a = sample();
        assert_eq!(a, a.clone());
    }

    #[test]
    fn detection_result_field_difference_changes_equality() {
        let a = sample();
        let b = DetectionResult {
            severity: Severity::High,
            ..a.clone()
        };
        assert_ne!(a, b);
    }

    #[test]
    fn detection_result_debug_output() {
        let dbg = format!("{:?}", sample());
        assert!(dbg.contains("xss"));
        assert!(dbg.contains("Injection"));
        assert!(dbg.contains("CRITICAL") || dbg.contains("Critical"));
    }

    #[test]
    fn severity_ordering_is_declaration_order() {
        // 声明顺序：Critical < High < Medium < Low
        assert!(Severity::Critical < Severity::High);
        assert!(Severity::High < Severity::Medium);
        assert!(Severity::Medium < Severity::Low);
    }

    #[test]
    fn severity_max_is_the_least_severe() {
        // 陷阱记录：Ord 顺序与"严重程度"相反，故不能用 max() 取最严重
        assert_eq!(Severity::Critical.max(Severity::Low), Severity::Low);
    }
}
