// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! `SessionGuard::verify` 的威胁判定与 fail-closed 行为。
//! 生命周期（bind / rotate / revoke）在 `tests/session_lifecycle.rs`。

use security_rust::session::{
    Decision, MemoryStore, RequestContext, SessionConfig, SessionGuard, SessionThreat, StoreError,
};
use security_rust::session::store::{LoginPoint, SessionRecord, SessionStore};
use security_rust::Severity;

const NOW: u64 = 1_000_000;
const FP: &str = "ip=1.2.3.4|ua=curl";

/// 默认不带 `at` —— 避免测试因无关的 `TimestampSkew` 误报而失败。
/// 需要测时间窗口的用例自行设置 `at`。
fn ctx<'a>(token: &'a str, subject: &'a str, fp: &'a str) -> RequestContext<'a> {
    RequestContext {
        token,
        subject,
        fingerprint: fp,
        location: Some("CN-BJ"),
        coords: Some((39.9042, 116.4074)),
        signature: None,
        at: None,
    }
}

fn guard() -> SessionGuard<MemoryStore> {
    SessionGuard::new(MemoryStore::new(), SessionConfig::default())
}

/// 永远返回错误的存储后端，用于验证 fail-closed。
struct BrokenStore;

impl SessionStore for BrokenStore {
    fn put(&self, _r: SessionRecord) -> Result<(), StoreError> {
        Err(StoreError::Unavailable)
    }
    fn get(&self, _t: &str) -> Result<Option<SessionRecord>, StoreError> {
        Err(StoreError::Unavailable)
    }
    fn touch(&self, _t: &str, _n: u64) -> Result<(), StoreError> {
        Err(StoreError::Unavailable)
    }
    fn revoke(&self, _t: &str) -> Result<(), StoreError> {
        Err(StoreError::Unavailable)
    }
    fn revoke_subject(&self, _s: &str) -> Result<usize, StoreError> {
        Err(StoreError::Unavailable)
    }
    fn recent_logins(&self, _s: &str) -> Result<Vec<LoginPoint>, StoreError> {
        Err(StoreError::Unavailable)
    }
    fn record_login(&self, _s: &str, _p: LoginPoint) -> Result<(), StoreError> {
        Err(StoreError::Unavailable)
    }
    fn purge_expired(&self, _n: u64) -> Result<usize, StoreError> {
        Err(StoreError::Unavailable)
    }
}

// ── 门槛检查 ────────────────────────────────────────────────

#[test]
fn verify_unknown_token_blocks() {
    let g = guard();
    let v = g.verify(&ctx("ghost", "u1", FP), NOW);
    assert_eq!(v.decision, Decision::Block);
    assert_eq!(v.threats, vec![SessionThreat::TokenUnknown]);
    assert_eq!(v.severity, Severity::Critical);
}

#[test]
fn verify_empty_token_blocks_as_unknown() {
    // verify 不返回 Result，「客户端没给 token」是正常运行时情况（未登录请求），非编程错误
    let g = guard();
    let v = g.verify(&ctx("", "u1", FP), NOW);
    assert_eq!(v.decision, Decision::Block);
    assert_eq!(v.threats, vec![SessionThreat::TokenUnknown]);
}

#[test]
fn verify_revoked_token_blocks() {
    let g = guard();
    g.bind(&ctx("t1", "u1", FP), NOW).unwrap();
    g.revoke("t1").unwrap();
    let v = g.verify(&ctx("t1", "u1", FP), NOW);
    assert_eq!(v.decision, Decision::Block);
    assert_eq!(v.threats, vec![SessionThreat::TokenRevoked]);
}

#[test]
fn verify_revoked_distinct_from_unknown() {
    // 吊销与「从未存在」必须是不同威胁 —— 用户提示不同：请重新登录 vs 非法请求
    let g = guard();
    g.bind(&ctx("t1", "u1", FP), NOW).unwrap();
    g.revoke("t1").unwrap();
    let revoked = g.verify(&ctx("t1", "u1", FP), NOW);
    let unknown = g.verify(&ctx("ghost", "u1", FP), NOW);
    assert_ne!(revoked.threats, unknown.threats);
}

#[test]
fn verify_expired_token_blocks_with_low_severity() {
    let g = guard();
    g.bind(&ctx("t1", "u1", FP), NOW).unwrap();
    let v = g.verify(&ctx("t1", "u1", FP), NOW + 3_601);
    assert_eq!(v.decision, Decision::Block);
    assert_eq!(v.threats, vec![SessionThreat::TokenExpired]);
    assert_eq!(v.severity, Severity::Low, "过期是例行情况，非攻击");
}

#[test]
fn verify_expired_distinct_from_unknown() {
    let g = guard();
    g.bind(&ctx("t1", "u1", FP), NOW).unwrap();
    let expired = g.verify(&ctx("t1", "u1", FP), NOW + 3_601);
    let unknown = g.verify(&ctx("ghost", "u1", FP), NOW + 3_601);
    assert_ne!(expired.threats, unknown.threats);
}

#[test]
fn verify_boundary_expires_at_equals_now_is_expired() {
    let g = guard();
    g.bind(&ctx("t1", "u1", FP), NOW).unwrap();
    let v = g.verify(&ctx("t1", "u1", FP), NOW + 3_600);
    assert_eq!(v.threats, vec![SessionThreat::TokenExpired]);
}

#[test]
fn verify_one_second_before_expiry_is_allowed() {
    let g = guard();
    g.bind(&ctx("t1", "u1", FP), NOW).unwrap();
    let v = g.verify(&ctx("t1", "u1", FP), NOW + 3_599);
    assert!(v.is_allowed(), "got {:?}", v.threats);
}

// ── 累积检查 ────────────────────────────────────────────────

#[test]
fn verify_valid_request_is_allowed() {
    let g = guard();
    g.bind(&ctx("t1", "u1", FP), NOW).unwrap();
    let v = g.verify(&ctx("t1", "u1", FP), NOW + 10);
    assert!(v.is_allowed(), "误报: {:?}", v.threats);
    assert!(v.threats.is_empty());
    assert_eq!(v.severity, Severity::Low);
}

#[test]
fn verify_fingerprint_mismatch_is_hijack_block() {
    let g = guard();
    g.bind(&ctx("t1", "u1", FP), NOW).unwrap();
    let v = g.verify(&ctx("t1", "u1", "fp2"), NOW + 10);
    assert_eq!(v.decision, Decision::Block);
    assert_eq!(v.severity, Severity::Critical);
    assert_eq!(v.threats, vec![SessionThreat::FingerprintMismatch]);
}

#[test]
fn verify_signature_mismatch_is_tamper_block() {
    let g = guard();
    let mut c = ctx("t1", "u1", FP);
    c.signature = Some("mac-original");
    g.bind(&c, NOW).unwrap();

    let mut c2 = ctx("t1", "u1", FP);
    c2.signature = Some("mac-tampered");
    let v = g.verify(&c2, NOW + 10);
    assert_eq!(v.decision, Decision::Block);
    assert!(v.threats.contains(&SessionThreat::SignatureInvalid));
}

#[test]
fn verify_signature_missing_when_baseline_had_one() {
    let g = guard();
    let mut c = ctx("t1", "u1", FP);
    c.signature = Some("mac-original");
    g.bind(&c, NOW).unwrap();

    let v = g.verify(&ctx("t1", "u1", FP), NOW + 10); // 无签名
    assert_eq!(v.decision, Decision::Block);
    assert_eq!(v.threats, vec![SessionThreat::SignatureMissing]);
}

#[test]
fn verify_matching_signature_allows() {
    let g = guard();
    let mut c = ctx("t1", "u1", FP);
    c.signature = Some("mac-original");
    g.bind(&c, NOW).unwrap();

    let mut c2 = ctx("t1", "u1", FP);
    c2.signature = Some("mac-original");
    assert!(g.verify(&c2, NOW + 10).is_allowed());
}

#[test]
fn verify_no_signature_on_either_side_allows() {
    // 调用方不使用签名时不该被拦
    let g = guard();
    g.bind(&ctx("t1", "u1", FP), NOW).unwrap();
    assert!(g.verify(&ctx("t1", "u1", FP), NOW + 10).is_allowed());
}

#[test]
fn verify_timestamp_skew_challenges() {
    let g = guard();
    g.bind(&ctx("t1", "u1", FP), NOW).unwrap();
    let mut c = ctx("t1", "u1", FP);
    c.at = Some(NOW + 3_601); // 偏离 3601 秒 > 300
    let v = g.verify(&c, NOW);
    assert_eq!(v.decision, Decision::Challenge);
    assert!(v.threats.contains(&SessionThreat::TimestampSkew));
}

#[test]
fn verify_timestamp_within_skew_allows() {
    let g = guard();
    g.bind(&ctx("t1", "u1", FP), NOW).unwrap();
    let mut c = ctx("t1", "u1", FP);
    c.at = Some(NOW + 10 + 299); // 偏离 299 <= 300
    assert!(g.verify(&c, NOW + 10).is_allowed());
}

#[test]
fn verify_absent_timestamp_skips_skew_check() {
    let g = guard();
    g.bind(&ctx("t1", "u1", FP), NOW).unwrap();
    // at = None（helper 默认），即使 now 前移 1000 秒（远超 300 秒窗口）
    // 也不报 TimestampSkew —— 缺时间戳时该检查整体跳过
    assert!(g.verify(&ctx("t1", "u1", FP), NOW + 1_000).is_allowed());
}

#[test]
fn verify_location_change_challenges() {
    let g = guard();
    g.bind(&ctx("t1", "u1", FP), NOW).unwrap(); // CN-BJ
    let mut c = ctx("t1", "u1", FP);
    c.location = Some("US-NY");
    c.coords = None;
    let v = g.verify(&c, NOW + 600);
    assert_eq!(v.decision, Decision::Challenge);
    assert!(v.threats.contains(&SessionThreat::LocationChanged));
    assert!(
        !v.threats
            .iter()
            .any(|t| matches!(t, SessionThreat::ImpossibleTravel { .. })),
        "无坐标时不该报不可能旅行"
    );
}

#[test]
fn verify_impossible_travel_blocks() {
    let g = guard();
    g.bind(&ctx("t1", "u1", FP), NOW).unwrap(); // 北京
    let mut c = ctx("t1", "u1", FP);
    c.location = Some("US-NY");
    c.coords = Some((40.7128, -74.0060));
    // 1 小时后；留一点余量避免踩到 expires_at <= now 的过期边界
    let v = g.verify(&c, NOW + 3_500);
    assert_eq!(v.decision, Decision::Block);
    assert!(
        v.threats
            .iter()
            .any(|t| matches!(t, SessionThreat::ImpossibleTravel { .. })),
        "got {:?}",
        v.threats
    );
}

#[test]
fn verify_missing_location_on_either_side_is_not_a_threat() {
    // 调用方可能只在部分请求提供位置，缺失不该产生误报
    let g = SessionGuard::new(MemoryStore::new(), SessionConfig::default());
    let mut c = ctx("t1", "u1", FP);
    c.location = None;
    c.coords = None;
    g.bind(&c, NOW).unwrap();

    let mut c2 = ctx("t1", "u1", FP);
    c2.location = Some("CN-BJ");
    let v = g.verify(&c2, NOW + 10);
    assert!(
        !v.threats.contains(&SessionThreat::LocationChanged),
        "记录侧无位置时不该报异地: {:?}",
        v.threats
    );
}

#[test]
fn verify_multiple_threats_accumulate() {
    let g = guard();
    let mut c = ctx("t1", "u1", FP);
    c.signature = Some("mac-original");
    g.bind(&c, NOW).unwrap();

    let mut bad = ctx("t1", "u1", "DIFFERENT-FP");
    bad.signature = Some("mac-tampered");
    bad.location = Some("US-NY");
    bad.coords = None;
    bad.at = Some(NOW + 100_000);

    let v = g.verify(&bad, NOW + 10);
    assert!(v.threats.contains(&SessionThreat::FingerprintMismatch));
    assert!(v.threats.contains(&SessionThreat::SignatureInvalid));
    assert!(v.threats.contains(&SessionThreat::LocationChanged));
    assert!(v.threats.contains(&SessionThreat::TimestampSkew));
    assert_eq!(v.decision, Decision::Block, "Block 压过 Challenge");
    assert_eq!(v.severity, Severity::Critical);
}

// ── fail-closed ─────────────────────────────────────────────

#[test]
fn verify_fails_closed_when_store_unavailable() {
    let g = SessionGuard::new(BrokenStore, SessionConfig::default());
    let v = g.verify(&ctx("t1", "u1", FP), NOW);
    assert_eq!(
        v.decision,
        Decision::Block,
        "后端故障绝不能放行 —— 这是可被攻击者主动触发的绕过"
    );
    assert_eq!(v.threats, vec![SessionThreat::StoreUnavailable]);
}

#[test]
fn bind_propagates_store_failure_as_error() {
    // 登录路径要让调用方知道「会话没建起来」，而不是拿到看着成功的 verdict
    let g = SessionGuard::new(BrokenStore, SessionConfig::default());
    assert!(g.bind(&ctx("t1", "u1", FP), NOW).is_err());
}
