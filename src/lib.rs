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
