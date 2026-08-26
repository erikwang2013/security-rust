// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity};
use regex::Regex;
use std::sync::LazyLock;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn det() -> LdapInjectionDetector {
        LdapInjectionDetector
    }

    fn assert_hit(input: &str) {
        let r = det()
            .detect(input)
            .expect("expected LDAP injection detection");
        assert_eq!(r.attack_type, "ldap_injection");
        assert_eq!(r.category, AttackCategory::Injection);
        assert_eq!(r.severity, Severity::High);
        assert!(!r.matched_pattern.is_empty(), "matched_pattern empty");
        assert!(
            r.offset <= input.len(),
            "offset {} > len {}",
            r.offset,
            input.len()
        );
    }

    #[test]
    fn name_is_ldap_injection() {
        assert_eq!(det().name(), "ldap_injection");
    }

    #[test]
    fn detects_common_payloads() {
        for input in [
            "(&(uid=admin)(!(|(cn=*))))",
            "(&(cn=user))",
            "(|(cn=admin))",
            "*(cn=*)",
            "(!(uid=*))",
            "(objectClass=*)",
            ")(&(uid=admin))",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn benign_inputs_not_detected() {
        for input in [
            "Hello, this is a normal text input. Nothing suspicious here.",
            "Please enter your username and password",
            "The directory contains user records",
            "uid=admin",
            "cn=test",
        ] {
            assert!(det().detect(input).is_none(), "false positive: {input}");
        }
    }

    #[test]
    fn edge_cases() {
        assert!(det().detect("").is_none());
        assert!(det().detect(" \t\n ").is_none());
        assert!(det().detect("你好世界 こんにちは").is_none());
        // near misses: attribute present but not in filter form
        assert!(det().detect("(uidadmin)").is_none());
        assert!(det().detect("(xuid=1)").is_none());
        assert!(det().detect("user (uid) admin").is_none());
    }

    #[test]
    fn obfuscated_variants_detected() {
        for input in ["(&(UID=admin))", "( uid =*)", "( cn = * )"] {
            assert_hit(input);
        }
    }
}
