// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity};
use regex::Regex;
use std::sync::LazyLock;

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)<script[\s/>]").unwrap(),
        Regex::new(r"(?i)on(?:error|load|click|mouse(?:over|out|down|up|move)|key(?:down|up|press)|focus|blur|change|submit|reset|scroll|resize|abort|select|start|drag|drop|play|pause|ended|volumechange|animationstart|animationend|transitionend|touchstart|touchend|pointerdown|pointerup|wheel|auxclick|canplay|canplaythrough|close|cuechange|dblclick|durationchange|emptied|fullscreenchange|gotpointercapture|input|invalid|loadeddata|loadedmetadata|loadstart|lostpointercapture|offline|online|pagehide|pageshow|popstate|progress|ratechange|securitypolicyviolation|seeked|seeking|show|stalled|suspend|timeupdate|toggle|waiting)\s*=").unwrap(),
        Regex::new(r"(?i)javascript\s*:").unwrap(),
        Regex::new(r"(?i)<svg[\s/>]").unwrap(),
        Regex::new(r"(?i)expression\s*\(").unwrap(),
        Regex::new(r"(?i)<iframe[\s/>]").unwrap(),
        Regex::new(r"(?i)<embed[\s/>]").unwrap(),
        Regex::new(r"(?i)<object[\s/>]").unwrap(),
        Regex::new(r"(?i)vbscript\s*:").unwrap(),
        Regex::new(r"(?i)data\s*:\s*text/html").unwrap(),
        Regex::new(r"(?i)<link[\s/>]").unwrap(),
        Regex::new(r"(?i)<meta[\s/>]").unwrap(),
        Regex::new(r"(?i)eval\s*\(").unwrap(),
        Regex::new(r"(?i)fromCharCode\s*\(").unwrap(),
        Regex::new(r"(?i)document\.cookie").unwrap(),
        Regex::new(r"(?i)document\.write\s*\(").unwrap(),
        Regex::new(r"(?i)window\.location").unwrap(),
    ]
});

pub struct XssDetector;

impl Detector for XssDetector {
    fn name(&self) -> &'static str {
        "xss"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "xss".into(),
                    category: AttackCategory::Injection,
                    severity: Severity::Critical,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "XSS cross-site scripting detected".into(),
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det() -> XssDetector {
        XssDetector
    }

    fn assert_hit(input: &str) {
        let r = det().detect(input).expect("expected XSS detection");
        assert_eq!(r.attack_type, "xss");
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
    fn name_is_xss() {
        assert_eq!(det().name(), "xss");
    }

    #[test]
    fn detects_common_payloads() {
        for input in [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(document.cookie)",
            "<svg onload=alert(1)>",
            "eval('alert(1)')",
            "<iframe src=\"//evil.com\"></iframe>",
            "data:text/html,<script>alert(1)</script>",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn benign_inputs_not_detected() {
        for input in [
            "Hello, this is a normal text input. Nothing suspicious here.",
            "The weather today is sunny with a high of 25 degrees.",
            "Please call the office at 555-1234 for assistance.",
            "Welcome to our website, please enjoy your stay.",
        ] {
            assert!(det().detect(input).is_none(), "false positive: {input}");
        }
    }

    #[test]
    fn edge_cases() {
        assert!(det().detect("").is_none());
        assert!(det().detect("   \t\n  ").is_none());
        assert!(det().detect("こんにちは世界 你好").is_none());
        // near misses: keyword present but not the payload form
        assert!(det().detect("script alert(1)").is_none());
        assert!(det().detect("javascript alert(1)").is_none());
        assert!(det().detect("evaluate this expression carefully").is_none());
    }

    #[test]
    fn obfuscated_variants_detected() {
        for input in [
            "<SCRIPT>alert(1)</SCRIPT>",
            "<img src=x OnErRoR=alert(1)>",
            "JaVaScRiPt:alert(1)",
            "<SVG/onload=alert(1)>",
        ] {
            assert_hit(input);
        }
    }
}
