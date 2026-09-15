// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

pub mod geo;
pub mod guard;
pub mod store;

use crate::Severity;

pub use guard::SessionGuard;
pub use store::{LoginPoint, MemoryStore, SessionRecord, SessionStore};

/// 一次请求的全部输入，字段由调用方填写。
#[derive(Debug, Clone)]
pub struct RequestContext<'a> {
    /// 调用方签发的 token 值。`verify` 中为空 ⇒ `TokenUnknown`。
    pub token: &'a str,
    /// 用户标识。**仅 `bind` 使用，`verify` 完全忽略它**：每请求校验的身份
    /// 一律取自服务端 [`SessionRecord`]（异地历史按 `record.subject` 聚合），
    /// 请求方提供的 subject 不可信。
    ///
    /// 因此中间件里传 `subject: ""` 是合法的 —— `verify` 不看这个字段
    /// （`bind` 才要求非空）。也正因如此，**绝不要**把请求头里的用户标识
    /// 填进来当身份：现在它进不了判定，将来重构也未必。
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
    /// 登录时未设签名基线，但本请求提供了签名。
    SignatureUnexpected,
    LocationChanged,
    ImpossibleTravel {
        kmh: f64,
    },
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
            SessionThreat::LocationChanged
            | SessionThreat::TimestampSkew
            | SessionThreat::SignatureUnexpected => Severity::Medium,
            SessionThreat::TokenExpired => Severity::Low,
        }
    }

    /// 该威胁对应的处置建议。
    pub fn decision(&self) -> Decision {
        match self {
            SessionThreat::LocationChanged
            | SessionThreat::TimestampSkew
            | SessionThreat::SignatureUnexpected => Decision::Challenge,
            _ => Decision::Block,
        }
    }
}

/// 人类可读的威胁描述，供日志直接打印。
impl std::fmt::Display for SessionThreat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionThreat::TokenUnknown => write!(f, "unknown token"),
            SessionThreat::TokenExpired => write!(f, "token expired"),
            SessionThreat::TokenRevoked => write!(f, "token revoked"),
            SessionThreat::FingerprintMismatch => write!(f, "fingerprint mismatch"),
            SessionThreat::SignatureInvalid => write!(f, "signature invalid"),
            SessionThreat::SignatureMissing => write!(f, "signature missing"),
            SessionThreat::SignatureUnexpected => write!(f, "unexpected signature"),
            SessionThreat::LocationChanged => write!(f, "location changed"),
            // km/h 是这条判定最有用的信息，不能让它只存在于 Debug 形状里
            SessionThreat::ImpossibleTravel { kmh } => {
                write!(f, "impossible travel ({kmh:.0} km/h)")
            }
            SessionThreat::TimestampSkew => write!(f, "timestamp skew"),
            SessionThreat::StoreUnavailable => write!(f, "session store unavailable"),
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

/// 状态标签，与 [`Severity`] 同样用大写 —— 这三种是处置结论，不是描述。
impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Decision::Allow => write!(f, "ALLOW"),
            Decision::Challenge => write!(f, "CHALLENGE"),
            Decision::Block => write!(f, "BLOCK"),
        }
    }
}

/// 一次校验的结论。
#[derive(Debug, Clone, PartialEq)]
pub struct SessionVerdict {
    pub decision: Decision,
    /// 最严重威胁的严重度；**无威胁（放行）时为 `None`**。
    ///
    /// 不拿 `Severity::Low` 占位：占位值在日志里跟「发现了一条低危」长得一模一样，
    /// 一条完全放行的正常请求会被读成有发现。没有威胁就是没有严重度，由类型说明。
    pub severity: Option<Severity>,
    pub threats: Vec<SessionThreat>,
}

impl SessionVerdict {
    /// 无任何威胁：放行，`severity` 为 `None`。
    pub fn allow() -> Self {
        Self {
            decision: Decision::Allow,
            severity: None,
            threats: Vec::new(),
        }
    }

    /// 单个威胁。
    pub fn single(threat: SessionThreat) -> Self {
        Self::from_threats(vec![threat])
    }

    /// 由威胁列表聚合：decision 取最严格者，severity 取最严重者（空列表 ⇒ `None`）。
    ///
    /// `Severity` 不提供任何序（派生 `Ord` 会按声明顺序 Critical < Low，与严重程度相反），
    /// 因此严重度比较一律走显式的 `severity_rank`；decision 的比较则可用 `Decision` 的 `Ord`。
    pub fn from_threats(threats: Vec<SessionThreat>) -> Self {
        if threats.is_empty() {
            return Self::allow();
        }
        let decision = threats
            .iter()
            .map(SessionThreat::decision)
            .max()
            .unwrap_or(Decision::Block);
        // 走到这里 threats 必非空，`max_by_key` 必为 `Some`；用 `Option` 承接而不是
        // 补一个不可能失败的 `unwrap_or` 占位值，正是为了让 `None` 只表示「无威胁」
        let severity = threats
            .iter()
            .map(SessionThreat::severity)
            .max_by_key(severity_rank);
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

/// 严重度权重，数值越大越严重。这是 `Severity` 唯一的排序依据。
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
        // Severity 没有任何 Ord，rank 是它唯一的严重度排序依据
        assert!(severity_rank(&Severity::Critical) > severity_rank(&Severity::Low));
    }

    #[test]
    fn empty_threats_yield_allow() {
        let v = SessionVerdict::from_threats(vec![]);
        assert_eq!(v.decision, Decision::Allow);
        assert!(v.is_allowed());
        assert!(v.threats.is_empty());
        assert_eq!(v.severity, None, "放行时没有发现，就没有严重度");
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
        assert_eq!(v.severity, Some(Severity::Critical));
        assert_eq!(v.decision, Decision::Block);
    }

    #[test]
    fn single_threat_maps_correctly() {
        let v = SessionVerdict::single(SessionThreat::TokenExpired);
        assert_eq!(v.decision, Decision::Block);
        assert_eq!(v.severity, Some(Severity::Low));
    }

    #[test]
    fn display_is_human_readable_not_debug() {
        assert_eq!(Decision::Challenge.to_string(), "CHALLENGE");
        assert_eq!(SessionThreat::TokenExpired.to_string(), "token expired");
        assert_eq!(
            SessionThreat::StoreUnavailable.to_string(),
            "session store unavailable"
        );
        // km/h 必须真的出现在输出里，而不是只留在 Debug 形状的内层
        assert_eq!(
            SessionThreat::ImpossibleTravel { kmh: 11_205.4 }.to_string(),
            "impossible travel (11205 km/h)"
        );
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
        assert_eq!(
            SessionThreat::SignatureUnexpected.severity(),
            Severity::Medium
        );
    }

    #[test]
    fn only_advisory_threats_challenge() {
        // 这三项是「信号」而非「结论」：可能只是出差 / 时钟漂移 / 调用方
        // 与自己行为不一致，先二次验证而不是直接拒绝
        assert_eq!(
            SessionThreat::LocationChanged.decision(),
            Decision::Challenge
        );
        assert_eq!(SessionThreat::TimestampSkew.decision(), Decision::Challenge);
        assert_eq!(
            SessionThreat::SignatureUnexpected.decision(),
            Decision::Challenge
        );
        // 其余一律 Block
        assert_eq!(SessionThreat::TokenExpired.decision(), Decision::Block);
        assert_eq!(SessionThreat::StoreUnavailable.decision(), Decision::Block);
    }

    #[test]
    fn errors_display_and_source() {
        assert_eq!(
            SessionError::EmptyToken.to_string(),
            "token must not be empty"
        );
        assert_eq!(
            SessionError::UnknownSession.to_string(),
            "session not found or no longer valid"
        );
        assert_eq!(
            StoreError::Unavailable.to_string(),
            "session store unavailable"
        );
        assert_eq!(StoreError::Corrupt.to_string(), "session store corrupt");
        let e = SessionError::from(StoreError::Corrupt);
        assert!(std::error::Error::source(&e).is_some());
        assert!(std::error::Error::source(&SessionError::EmptyToken).is_none());
    }
}
