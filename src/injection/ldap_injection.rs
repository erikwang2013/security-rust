use regex::Regex;
use std::sync::LazyLock;
use crate::{AttackCategory, DetectionResult, Detector, Severity};

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"\(\s*&").unwrap(),
        Regex::new(r"\(\s*\|").unwrap(),
        Regex::new(r"\(\s*!").unwrap(),
        Regex::new(r"\*\(cn=").unwrap(),
        Regex::new(r"\(\s*objectClass\s*=").unwrap(),
        Regex::new(r"\(\s*uid\s*=").unwrap(),
        Regex::new(r"\)\(\s*").unwrap(),
        Regex::new(r"\(\s*cn\s*=").unwrap(),
    ]
});

pub struct LdapInjectionDetector;

impl Detector for LdapInjectionDetector {
    fn name(&self) -> &'static str {
        "ldap_injection"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "ldap_injection".into(),
                    category: AttackCategory::Injection,
                    severity: Severity::High,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "LDAP injection detected".into(),
                });
            }
        }
        None
    }
}
