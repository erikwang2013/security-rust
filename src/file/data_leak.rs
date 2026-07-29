// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity};

static CC_PAN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b").unwrap()
});

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
        Regex::new(r"-----BEGIN\s*(?:RSA\s*)?PRIVATE\s*KEY").unwrap(),
        Regex::new(r"-----BEGIN\s*CERTIFICATE").unwrap(),
        Regex::new(r"-----BEGIN\s*DSA\s*PRIVATE").unwrap(),
        Regex::new(r"-----BEGIN\s*EC\s*PRIVATE").unwrap(),
        Regex::new(r"-----BEGIN\s*PGP\s*PRIVATE").unwrap(),
        Regex::new(r"sk-[A-Za-z0-9]{32,}").unwrap(),
        Regex::new(r"(?i)mongodb(?:\+srv)?://[^/\s]+").unwrap(),
        Regex::new(r"(?i)mysql://[^/\s]+").unwrap(),
        Regex::new(r"(?i)postgres(?:ql)?://[^/\s]+").unwrap(),
        Regex::new(r"(?i)redis://[^/\s]+").unwrap(),
        Regex::new(r"(?i)jdbc:[a-z]+://").unwrap(),
        Regex::new(r"(?i)eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").unwrap(),
    ]
});

fn luhn_valid(pan: &str) -> bool {
    let digits: Vec<u8> = pan
        .as_bytes()
        .iter()
        .filter_map(|b| {
            if b.is_ascii_digit() {
                Some(b - b'0')
            } else {
                None
            }
        })
        .collect();
    if digits.len() < 13 {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = d as u32 * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                d as u32
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

pub struct DataLeakDetector;

impl Detector for DataLeakDetector {
    fn name(&self) -> &'static str {
        "data_leak"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        if let Some(m) = CC_PAN.find(input)
            && luhn_valid(m.as_str())
        {
            return Some(DetectionResult {
                attack_type: "data_leak".into(),
                category: AttackCategory::File,
                severity: Severity::Critical,
                matched_pattern: m.as_str().to_string(),
                offset: m.start(),
                message: "Sensitive data leak detected (credit card)".into(),
            });
        }
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "data_leak".into(),
                    category: AttackCategory::File,
                    severity: Severity::Critical,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "Sensitive data leak detected".into(),
                });
            }
        }
        None
    }
}
