// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;

pub mod data;
pub mod file;
pub mod injection;
pub mod protocol;
pub mod result;
pub mod scanner;

pub use result::{AttackCategory, DetectionResult, Severity};
pub use scanner::{Scanner, ScannerBuilder};

pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
    fn detect(&self, input: &str) -> Option<DetectionResult>;
}

pub(crate) fn regex_detect(
    patterns: &[Regex],
    name: &'static str,
    category: AttackCategory,
    severity: Severity,
    message: &'static str,
    input: &str,
) -> Option<DetectionResult> {
    for re in patterns {
        if let Some(m) = re.find(input) {
            return Some(DetectionResult {
                attack_type: name.to_string(),
                category,
                severity,
                matched_pattern: m.as_str().to_string(),
                offset: m.start(),
                message: message.into(),
            });
        }
    }
    None
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;

    pub(crate) fn assert_detected<D: Detector>(
        d: &D,
        input: &str,
        category: AttackCategory,
        severity: Severity,
    ) {
        let r = d.detect(input).expect("expected detection");
        assert_eq!(r.attack_type, d.name());
        assert_eq!(r.category, category);
        assert_eq!(r.severity, severity);
        assert!(!r.matched_pattern.is_empty(), "matched_pattern empty");
        assert!(
            r.offset <= input.len(),
            "offset {} > len {}",
            r.offset,
            input.len()
        );
        assert_eq!(
            &input[r.offset..r.offset + r.matched_pattern.len()],
            r.matched_pattern
        );
        assert!(!r.message.is_empty());
    }

    pub(crate) fn assert_clean<D: Detector>(d: &D, input: &str) {
        assert!(d.detect(input).is_none(), "not detected: {input:?}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detector_trait_object_is_send_sync() {
        let detector: Box<dyn Detector> = Box::new(injection::XssDetector);
        assert_eq!(detector.name(), "xss");
    }

    #[test]
    fn detector_name_is_static_str() {
        let name: &'static str = injection::XssDetector.name();
        assert_eq!(name, "xss");
    }
}
