// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

pub mod geo;
pub mod guard;
pub mod store;

use crate::Severity;

pub use store::{MemoryStore, SessionStore};

/// 一次请求的全部输入，字段由调用方填写。
#[derive(Debug, Clone)]
pub struct RequestContext<'a> {
    /// 调用方签发的 token 值。`verify` 中为空 ⇒ `TokenUnknown`。
    pub token: &'a str,
    /// 用户标识。异地登录历史按它聚合，而非按 token。
    pub subject: &'a str,
    /// 客户端指纹（如 IP + User-Agent 的规范化拼接），登录时绑定。
    pub fingerprint: &'a str,
    /// 区域标识，如 "CN-BJ"。由调用方用已有 geo 库从 IP 解析。
    pub location: Option<&'a str>,
    /// (纬度, 经度)，用于「不可能旅行」判定。
    pub coords: Option<(f64, f64)>,
    /// 调用方算好的 MAC。
    pub signature: Option<&'a str>,
    /// 请求自称的时间（unix 秒，如 token 内嵌的 iat）。
    pub at: Option<u64>,
}

/// 会话安全威胁。见 spec 的判定与处置映射表。
#[derive(Debug, Clone, PartialEq)]
pub enum SessionThreat {
    TokenUnknown,
    TokenExpired,
    TokenRevoked,
    FingerprintMismatch,
    SignatureInvalid,
    SignatureMissing,
    LocationChanged,
    ImpossibleTravel { kmh: f64 },
    TimestampSkew,
    StoreUnavailable,
}

impl SessionThreat {
    /// 该威胁对应的严重度。映射是固定默认值，不做配置。
    pub fn severity(&self) -> Severity {
        match self {
            SessionThreat::TokenUnknown
            | SessionThreat::FingerprintMismatch
            | SessionThreat::SignatureInvalid
            | SessionThreat::ImpossibleTravel { .. } => Severity::Critical,
            SessionThreat::TokenRevoked
            | SessionThreat::SignatureMissing
            | SessionThreat::StoreUnavailable => Severity::High,
            SessionThreat::LocationChanged | SessionThreat::TimestampSkew => Severity::Medium,
            SessionThreat::TokenExpired => Severity::Low,
        }
    }

    /// 该威胁对应的处置建议。
    pub fn decision(&self) -> Decision {
        match self {
            SessionThreat::LocationChanged | SessionThreat::TimestampSkew => Decision::Challenge,
            _ => Decision::Block,
        }
    }
}

/// 严格度递增（声明顺序即 Ord 顺序），取最严格者作为最终决策。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Decision {
    Allow,
    Challenge,
    Block,
}

/// 一次校验的结论。
#[derive(Debug, Clone, PartialEq)]
pub struct SessionVerdict {
    pub decision: Decision,
    /// 无威胁时为 `Severity::Low` 占位 —— 此时该字段无意义，调用方应只读 `decision`。
    pub severity: Severity,
    pub threats: Vec<SessionThreat>,
}

impl SessionVerdict {
    /// 无任何威胁：放行。
    pub fn allow() -> Self {
        Self {
            decision: Decision::Allow,
            severity: Severity::Low,
            threats: Vec::new(),
        }
    }

    /// 单个威胁。
    pub fn single(threat: SessionThreat) -> Self {
        Self::from_threats(vec![threat])
    }

    /// 由威胁列表聚合：decision 取最严格者，severity 取最严重者。
    ///
    /// `Severity` 的 `Ord` 顺序是声明顺序（Critical 最小），与严重程度**相反**，
    /// 故此处用显式的 `severity_rank` 取最大，不能直接用 `max()`。
    pub fn from_threats(threats: Vec<SessionThreat>) -> Self {
        if threats.is_empty() {
            return Self::allow();
        }
        let decision = threats
            .iter()
            .map(SessionThreat::decision)
            .max()
            .unwrap_or(Decision::Block);
        let severity = threats
            .iter()
            .map(SessionThreat::severity)
            .max_by_key(severity_rank)
            .unwrap_or(Severity::Low);
        Self {
            decision,
            severity,
            threats,
        }
    }

    pub fn is_allowed(&self) -> bool {
        self.decision == Decision::Allow
    }
}

/// 严重度权重，数值越大越严重。与 `Severity` 的 `Ord` 顺序无关。
fn severity_rank(s: &Severity) -> u8 {
    match s {
        Severity::Low => 0,
        Severity::Medium => 1,
        Severity::High => 2,
        Severity::Critical => 3,
    }
}

/// 只放校准旋钮（阈值），不放策略。
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// 会话有效期（秒）。
    pub ttl_secs: u64,
    /// 不可能旅行的速度上限（km/h）。
    pub impossible_travel_kmh: f64,
    /// 请求自称时间与 `now` 的最大容忍偏离（秒）。
    pub timestamp_skew_secs: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            ttl_secs: 3600,
            impossible_travel_kmh: 900.0,
            timestamp_skew_secs: 300,
        }
    }
}

/// 存储后端故障。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    Unavailable,
    Corrupt,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Unavailable => write!(f, "session store unavailable"),
            StoreError::Corrupt => write!(f, "session store corrupt"),
        }
    }
}

impl std::error::Error for StoreError {}

/// 调用方误用，或后端故障向上传递。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    EmptyToken,
    EmptySubject,
    EmptyFingerprint,
    /// `rotate` 的旧 token 不存在、已吊销或已过期。
    UnknownSession,
    Store(StoreError),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::EmptyToken => write!(f, "token must not be empty"),
            SessionError::EmptySubject => write!(f, "subject must not be empty"),
            SessionError::EmptyFingerprint => write!(f, "fingerprint must not be empty"),
            SessionError::UnknownSession => write!(f, "session not found or no longer valid"),
            SessionError::Store(e) => write!(f, "session store error: {e}"),
        }
    }
}

impl std::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SessionError::Store(e) => Some(e),
            _ => None,
        }
    }
}

impl From<StoreError> for SessionError {
    fn from(e: StoreError) -> Self {
        SessionError::Store(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_ordering_strictest_is_block() {
        assert!(Decision::Allow < Decision::Challenge);
        assert!(Decision::Challenge < Decision::Block);
        assert_eq!(
            [Decision::Allow, Decision::Block, Decision::Challenge]
                .into_iter()
                .max()
                .unwrap(),
            Decision::Block
        );
    }

    #[test]
    fn severity_rank_is_not_declaration_order() {
        // Severity 的 Ord 声明顺序与严重程度相反，rank 必须独立于它
        assert!(severity_rank(&Severity::Critical) > severity_rank(&Severity::Low));
        assert!(Severity::Critical < Severity::Low); // 声明顺序确实是反的
    }

    #[test]
    fn empty_threats_yield_allow() {
        let v = SessionVerdict::from_threats(vec![]);
        assert_eq!(v.decision, Decision::Allow);
        assert!(v.is_allowed());
        assert!(v.threats.is_empty());
    }

    #[test]
    fn block_beats_challenge() {
        let v = SessionVerdict::from_threats(vec![
            SessionThreat::LocationChanged,     // Challenge
            SessionThreat::FingerprintMismatch, // Block
        ]);
        assert_eq!(v.decision, Decision::Block);
    }

    #[test]
    fn challenge_wins_when_no_block_present() {
        let v = SessionVerdict::from_threats(vec![
            SessionThreat::TimestampSkew,
            SessionThreat::LocationChanged,
        ]);
        assert_eq!(v.decision, Decision::Challenge);
    }

    #[test]
    fn severity_takes_the_most_severe_not_the_max() {
        let v = SessionVerdict::from_threats(vec![
            SessionThreat::TokenExpired,        // Low
            SessionThreat::FingerprintMismatch, // Critical
            SessionThreat::LocationChanged,     // Medium
        ]);
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.decision, Decision::Block);
    }

    #[test]
    fn single_threat_maps_correctly() {
        let v = SessionVerdict::single(SessionThreat::TokenExpired);
        assert_eq!(v.decision, Decision::Block);
        assert_eq!(v.severity, Severity::Low);
    }

    #[test]
    fn config_defaults_match_spec() {
        let c = SessionConfig::default();
        assert_eq!(c.ttl_secs, 3600);
        assert_eq!(c.impossible_travel_kmh, 900.0);
        assert_eq!(c.timestamp_skew_secs, 300);
    }

    #[test]
    fn threat_severity_mapping_matches_spec() {
        assert_eq!(SessionThreat::TokenUnknown.severity(), Severity::Critical);
        assert_eq!(
            SessionThreat::FingerprintMismatch.severity(),
            Severity::Critical
        );
        assert_eq!(
            SessionThreat::SignatureInvalid.severity(),
            Severity::Critical
        );
        assert_eq!(
            SessionThreat::ImpossibleTravel { kmh: 9_000.0 }.severity(),
            Severity::Critical
        );
        assert_eq!(SessionThreat::TokenRevoked.severity(), Severity::High);
        assert_eq!(SessionThreat::SignatureMissing.severity(), Severity::High);
        assert_eq!(SessionThreat::StoreUnavailable.severity(), Severity::High);
        assert_eq!(SessionThreat::TokenExpired.severity(), Severity::Low);
        assert_eq!(SessionThreat::LocationChanged.severity(), Severity::Medium);
        assert_eq!(SessionThreat::TimestampSkew.severity(), Severity::Medium);
    }

    #[test]
    fn only_location_and_skew_challenge() {
        assert_eq!(
            SessionThreat::LocationChanged.decision(),
            Decision::Challenge
        );
        assert_eq!(SessionThreat::TimestampSkew.decision(), Decision::Challenge);
        assert_eq!(SessionThreat::TokenExpired.decision(), Decision::Block);
        assert_eq!(SessionThreat::StoreUnavailable.decision(), Decision::Block);
    }

    #[test]
    fn errors_display_and_source() {
        assert!(!SessionError::EmptyToken.to_string().is_empty());
        assert!(!SessionError::UnknownSession.to_string().is_empty());
        assert!(!StoreError::Unavailable.to_string().is_empty());
        let e = SessionError::from(StoreError::Corrupt);
        assert!(std::error::Error::source(&e).is_some());
        assert!(std::error::Error::source(&SessionError::EmptyToken).is_none());
    }
}
