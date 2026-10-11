// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

// 内层属性必须出现在任何 item 之前；版权头是注释，放它上面不违反 rustc 规则
// （Linux 内核的 SPDX 头同样是这个位置）。本库至今零 unsafe，用 forbid 把这条
// 从口头承诺升级成编译期强制 —— 新增一句 unsafe 会直接编译失败。
#![forbid(unsafe_code)]

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
//! let first = results.first().expect("xss should be detected");
//! assert_eq!(first.attack_type, "xss");
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

/// 所有检测器的唯一契约：一个名字，一次检测。
///
/// 32 个内置检测器都只实现这两个方法。`session` / `throttle` **不实现**本 trait
/// —— 它们是有状态的，输入不是单个字符串（token + 指纹 + 位置 + 时间），也不在
/// [`Scanner`] 的装配范围内，见各自模块。
///
/// 实现契约（`tests/invariants.rs` 对全部内置实现逐个核验）：
/// - [`name`](Detector::name) 非空、snake_case、全局唯一；
/// - [`detect`](Detector::detect) 返回的 [`DetectionResult::attack_type`] 必须等于
///   `name()`，且命中时 `matched_pattern` 非空；
/// - 同一实例的 `name()` 恒定（扫过任意输入都不变）；
/// - `Send + Sync`：`Scanner` 靠它把检测器跨线程共享。
pub trait Detector: Send + Sync {
    /// 检测器名：snake_case 且全局唯一，同时是
    /// [`Scanner::scan_with`] 的过滤键与 [`DetectionResult::attack_type`] 的取值。
    ///
    /// 返回 `&'static str`：名字是编译期字面量，调用方可以收集成静态名单长期保存，
    /// 不受检测器生命周期约束。
    fn name(&self) -> &'static str;

    /// 扫描一个输入：命中返回 `Some`，未命中返回 `None`，**至多一条**结果。
    ///
    /// 返回字段的契约（`tests/invariants.rs` 与各检测器自测逐一核验）：
    /// - `attack_type == self.name()`；
    /// - `offset` 是 `input` 内的**字节**偏移（UTF-8 字节下标，不是字符数）；
    /// - `matched_pattern` 恰好是 `&input[offset..offset + matched_pattern.len()]`，
    ///   即命中片段本身；
    /// - 有强弱两档的检测器先试强档：强档命中报声明的等级，未中再试弱档，弱档固定报
    ///   [`Severity::Low`]（弱信号，单条不构成拒绝理由，见 [`DetectionResult::severity`]）。
    ///
    /// 无状态：`&self` 只读，同一输入任意次调用结果相同；实现不得借检测写入内部状态
    /// （需要状态请用 `session` / `throttle` 这类独立模块）。
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
