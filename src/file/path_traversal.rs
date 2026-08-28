// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{regex_detect, AttackCategory, DetectionResult, Detector, Severity};

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"\.\./").unwrap(),
        Regex::new(r"\.\.\\").unwrap(),
        Regex::new(r"(?i)\.\.%2[Ff]").unwrap(),
        Regex::new(r"(?i)%2[Ee]%2[Ee]").unwrap(),
        Regex::new(r"(?i)php://filter").unwrap(),
        Regex::new(r"(?i)php://input").unwrap(),
        Regex::new(r"(?i)data://").unwrap(),
        Regex::new(r"(?i)expect://").unwrap(),
        Regex::new(r"(?i)phar://").unwrap(),
        Regex::new(r"(?i)zip://").unwrap(),
        Regex::new(r"(?i)glob://").unwrap(),
        Regex::new(r"%00").unwrap(),
        Regex::new(r"\x00").unwrap(),
    ]
});

pub struct PathTraversalDetector;

impl Detector for PathTraversalDetector {
    fn name(&self) -> &'static str {
        "path_traversal"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(&PATTERNS, self.name(), AttackCategory::File, Severity::Critical, "Path traversal attack detected", input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_returns_attack_type() {
        assert_eq!(PathTraversalDetector.name(), "path_traversal");
    }

    #[test]
    fn detects_dotdot_traversal() {
        for payload in [
            "../../../etc/passwd",
            "..\\..\\windows\\system32",
            "a/../../b",
        ] {
            let r = PathTraversalDetector
                .detect(payload)
                .unwrap_or_else(|| panic!("expected detection for {:?}", payload));
            assert_eq!(r.attack_type, "path_traversal");
            assert_eq!(r.category, AttackCategory::File);
            assert_eq!(r.severity, Severity::Critical);
            assert!(
                !r.matched_pattern.is_empty(),
                "matched_pattern empty for {:?}",
                payload
            );
            assert!(
                r.offset <= payload.len(),
                "offset out of range for {:?}",
                payload
            );
        }
    }

    #[test]
    fn detects_encoded_traversal() {
        for payload in [
            "..%2f..%2fetc/passwd",
            "..%2Fetc/passwd",
            "%2e%2e%2fetc/passwd",
            "%2E%2E/win.ini",
        ] {
            let r = PathTraversalDetector
                .detect(payload)
                .unwrap_or_else(|| panic!("expected detection for {:?}", payload));
            assert!(
                !r.matched_pattern.is_empty(),
                "matched_pattern empty for {:?}",
                payload
            );
            assert!(
                r.offset <= payload.len(),
                "offset out of range for {:?}",
                payload
            );
        }
    }

    #[test]
    fn detects_wrappers_and_null_bytes() {
        for payload in [
            "php://filter/convert.base64-encode/resource=config.php",
            "php://input",
            "data://text/plain;base64,PD9waHA=",
            "expect://id",
            "phar://archive.phar",
            "zip://archive.zip#a",
            "glob://*.php",
            "file%00.php",
        ] {
            let r = PathTraversalDetector
                .detect(payload)
                .unwrap_or_else(|| panic!("expected detection for {:?}", payload));
            assert!(
                !r.matched_pattern.is_empty(),
                "matched_pattern empty for {:?}",
                payload
            );
            assert!(
                r.offset <= payload.len(),
                "offset out of range for {:?}",
                payload
            );
        }
    }

    #[test]
    fn ignores_benign_inputs() {
        for input in [
            "Hello, this is a normal text input.",
            "etc/passwd",
            "a.b/c",
            "..",
            "...",
            "php:",
            "zip:archive.zip",
            "/etc/passwd",
        ] {
            assert!(
                PathTraversalDetector.detect(input).is_none(),
                "false positive: {:?}",
                input
            );
        }
    }

    #[test]
    fn edge_cases() {
        assert!(PathTraversalDetector.detect("").is_none());
        assert!(PathTraversalDetector.detect("   ").is_none());
        assert!(PathTraversalDetector.detect("…/…/秘密のファイル").is_none()); // unicode ellipsis
    }
}
