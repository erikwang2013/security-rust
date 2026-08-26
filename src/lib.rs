// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

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
