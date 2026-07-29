// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity};

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)Upgrade:\s*websocket").unwrap(),
        Regex::new(r"(?i)Sec-WebSocket-Key:").unwrap(),
        Regex::new(r"(?i)Origin:\s*null.*Upgrade").unwrap(),
        Regex::new(r"(?i)ws://").unwrap(),
    ]
});

pub struct WebSocketDetector;

impl Detector for WebSocketDetector {
    fn name(&self) -> &'static str {
        "websocket"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "websocket".into(),
                    category: AttackCategory::Protocol,
                    severity: Severity::High,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "WebSocket hijack attempt detected".into(),
                });
            }
        }
        None
    }
}
