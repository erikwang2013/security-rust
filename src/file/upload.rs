// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity};

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)<\?php").unwrap(),
        Regex::new(r"(?i)<\?=").unwrap(),
        Regex::new(r"(?i)<%\s*@").unwrap(),
        Regex::new(r"(?i)<%\s*=").unwrap(),
        Regex::new(r#"(?i)<script\s+language\s*=\s*["']?(?:php|vbscript|jscript)["']?"#).unwrap(),
        Regex::new(r"(?i)eval\s*\(\s*\$").unwrap(),
        Regex::new(r"(?i)system\s*\(\s*\$").unwrap(),
        Regex::new(r"(?i)exec\s*\(\s*\$").unwrap(),
        Regex::new(r"(?i)passthru\s*\(\s*\$").unwrap(),
        Regex::new(r"(?i)shell_exec\s*\(\s*\$").unwrap(),
        Regex::new(r"(?i)\$_GET\[").unwrap(),
        Regex::new(r"(?i)\$_POST\[").unwrap(),
        Regex::new(r"(?i)\$_REQUEST\[").unwrap(),
        Regex::new(r"(?i)\$_SERVER\[").unwrap(),
        Regex::new(r"(?i)base64_decode\s*\(").unwrap(),
    ]
});

pub struct UploadDetector;

impl Detector for UploadDetector {
    fn name(&self) -> &'static str {
        "upload"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "upload".into(),
                    category: AttackCategory::File,
                    severity: Severity::Critical,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "Malicious file upload detected".into(),
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttackCategory, Detector, Severity};

    #[test]
    fn name_returns_attack_type() {
        assert_eq!(UploadDetector.name(), "upload");
    }

    #[test]
    fn detects_php_tags() {
        for payload in [
            "<?php system($_GET['cmd']); ?>",
            "<?= shell_exec($_POST['cmd']) ?>",
            "<?php echo 'hello';",
        ] {
            let r = UploadDetector
                .detect(payload)
                .unwrap_or_else(|| panic!("expected detection for {:?}", payload));
            assert_eq!(r.attack_type, "upload");
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
    fn detects_asp_and_script_language_tags() {
        for payload in [
            "<% @ Page Language=\"C#\" %>",
            "<% = response.write(1) %>",
            "<script language='vbscript'>MsgBox 1</script>",
            "<script language=\"jscript\">x()</script>",
            "<script language=php>echo 1;</script>",
        ] {
            let r = UploadDetector
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
    fn detects_exec_functions_and_superglobals() {
        for payload in [
            "eval($code);",
            "system($cmd);",
            "exec($cmd);",
            "passthru($cmd);",
            "shell_exec($cmd);",
            "$_GET['cmd']",
            "$_POST['cmd']",
            "$_REQUEST['cmd']",
            "$_SERVER['REQUEST_URI']",
            "base64_decode('aGVsbG8=')",
        ] {
            let r = UploadDetector
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
            "php is a popular language",
            "<script>alert(1)</script>",
            "system('id')",
            "exec('ls')",
            "base64_decode",
            "$_GET",
            "eval()",
        ] {
            assert!(
                UploadDetector.detect(input).is_none(),
                "false positive: {:?}",
                input
            );
        }
    }

    #[test]
    fn edge_cases() {
        assert!(UploadDetector.detect("").is_none());
        assert!(UploadDetector.detect("   ").is_none());
        assert!(UploadDetector.detect("＜？php echo 1;").is_none()); // fullwidth angle bracket
        assert!(UploadDetector.detect("<? phpx echo 1;").is_none()); // space breaks the tag
    }
}
