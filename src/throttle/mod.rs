// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use std::fmt;

pub mod guard;
pub mod store;

/// 复用 session 模块的错误类型，本模块不新造 —— 后端故障的形状是一样的。
pub use crate::session::StoreError;

pub use guard::Throttle;
pub use store::{MemoryThrottleStore, ThrottleStore};

/// 只放校准旋钮，不放策略。
#[derive(Debug, Clone)]
pub struct ThrottleConfig {
    /// 窗口内允许的失败次数，达到即封禁。`0` 表示不给宽限：首次失败即封。
    pub threshold: u32,
    /// 计数窗口（秒）。`0` 表示失败互不相干（每次 `record_failure` 都从 1 起算）。
    pub window_secs: u64,
    /// 触发后的封禁时长（秒）。`0` 表示立即解封（仅记录，不拦人）。
    pub ban_secs: u64,
}

impl Default for ThrottleConfig {
    fn default() -> Self {
        Self {
            threshold: 5,
            window_secs: 60,
            ban_secs: 900,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThrottleDecision {
    /// 放行，`remaining` 为窗口内剩余可失败次数（可写进 X-RateLimit-* 响应头）。
    ///
    /// **`remaining == 0` 表示本请求应被拒绝**（额度已耗尽），不是「还能再试一次」；
    /// 调用方必须据此拒绝，否则最后一次额度形同虚设。仍叫 `Allow` 而非 `Banned`，
    /// 是因为此刻并没有封禁在生效 —— 例如 `ban_secs = 0` 的配置下，额度耗尽的 key
    /// 会一直落在这一支。
    Allow { remaining: u32 },
    /// 已封禁，`until` 是解封时刻（unix 秒）。`now >= until` 即视为已解封。
    Banned { until: u64 },
    /// 存储后端不可用，**本模块不替调用方做决定**。
    ///
    /// 与 session 模块的 fail-closed 有意不同：限流是纵深防御而非主认证闸门，
    /// 后端抖动时把全体用户挡在门外是自我 DoS，而放行只是暂时失去暴力破解防护
    /// —— 主认证闸门（SessionGuard）仍然在拦。调用方拿到这个变体后自行选择
    /// （建议：放行 + 告警）。
    ///
    /// 这条「不 fail-closed」是写死的设计，不是漏写的兜底：`Throttle::check` 里
    /// 只把 `Err` 映射到本变体，绝不映射到 `Banned`。
    ///
    /// 只由 [`guard::Throttle::check`] / [`guard::Throttle::check_any`] 产生。
    /// [`guard::Throttle::record_failure`] **没有这个变体**（它返回
    /// [`ThrottleOutcome`]，故障走 `Err`），所以调用方不必为它写死分支。
    Unavailable,
}

/// 状态标签，与 [`Severity`](crate::Severity) 同样用大写。
impl fmt::Display for ThrottleDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThrottleDecision::Allow { .. } => write!(f, "ALLOW"),
            ThrottleDecision::Banned { .. } => write!(f, "BANNED"),
            ThrottleDecision::Unavailable => write!(f, "UNAVAILABLE"),
        }
    }
}

/// `record_failure` 的结果。与 `check` 的 `ThrottleDecision` 不同，
/// 这里不存在 `Unavailable` —— 存储故障走 `Err` 返回，不混在正常结果里。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThrottleOutcome {
    /// 未达阈值：本次失败已记下，`remaining` 是窗口内剩余可失败次数。
    Allow { remaining: u32 },
    /// 本次失败达到阈值，已写入封禁；`until` 是解封时刻（unix 秒）。
    Banned { until: u64 },
}

impl fmt::Display for ThrottleOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThrottleOutcome::Allow { .. } => write!(f, "ALLOW"),
            ThrottleOutcome::Banned { .. } => write!(f, "BANNED"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_match_spec() {
        let c = ThrottleConfig::default();
        assert_eq!(c.threshold, 5, "got {:?}", c);
        assert_eq!(c.window_secs, 60, "got {:?}", c);
        assert_eq!(c.ban_secs, 900, "got {:?}", c);
    }

    #[test]
    fn decision_and_outcome_display_uppercase() {
        assert_eq!(
            ThrottleDecision::Allow { remaining: 3 }.to_string(),
            "ALLOW"
        );
        assert_eq!(ThrottleDecision::Banned { until: 7 }.to_string(), "BANNED");
        assert_eq!(ThrottleDecision::Unavailable.to_string(), "UNAVAILABLE");
        assert_eq!(ThrottleOutcome::Allow { remaining: 3 }.to_string(), "ALLOW");
        assert_eq!(ThrottleOutcome::Banned { until: 7 }.to_string(), "BANNED");
    }
}
