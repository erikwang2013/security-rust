// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! Rust 编写的攻击检测库：32 个无状态检测器（注入 / 协议 / 数据 / 文件四类）
//! + 三个有状态模块（会话安全、限流封禁、风险评分）。`[dependencies]` 只有 `regex`。
//!
//! ```text
//!       (o)(o)
//!    ⌕┬─────────┬!     甲哨 Sentri
//!     │ · · · · │       只报告，不拦截
//!     └──┬───┬──┘       32 detectors / 4 categories
//!       /     \         deps = regex ×1
//! ```
//!
//! 项目宠物 **甲哨 Sentri**：32 片甲是 32 个检测器，左钳的放大镜负责看，右钳的
//! 告示牌负责报，但两只钳子都不替调用方做决定（唯一的例外是
//! [`SessionGuard`]）。形象见 [`pet`] 模块。
//!
//! ```
//! use security_rust::Scanner;
//!
//! let results = Scanner::default().scan("<script>alert(1)</script>");
//! assert_eq!(results[0].attack_type, "xss");
//! ```

use regex::Regex;

pub mod data;
pub mod file;
pub mod injection;
pub mod pet;
pub mod protocol;
pub mod result;
pub mod scanner;
pub mod score;
pub mod session;
pub mod throttle;

pub use result::{AttackCategory, DetectionResult, Severity};
pub use scanner::{Scanner, ScannerBuilder};
pub use score::{RiskAssessment, RiskLevel, assess};
pub use session::{
    Decision, LoginPoint, MemoryStore, RequestContext, SessionConfig, SessionError, SessionGuard,
    SessionRecord, SessionStore, SessionThreat, SessionVerdict, StoreError,
};
pub use throttle::{
    MemoryThrottleStore, Throttle, ThrottleConfig, ThrottleDecision, ThrottleOutcome, ThrottleStore,
};

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
        // 断言是「必须干净」，所以只有在**检出**时才会 panic —— 报错信息必须
        // 说明是误报，而不是"未检出"（旧文案正好说反，读起来与事实相反）。
        assert!(d.detect(input).is_none(), "expected clean, but detected: {input:?}");
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
