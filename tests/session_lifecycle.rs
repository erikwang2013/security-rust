// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 会话生命周期：`bind`（建会话 / 绑指纹 / 记位置）与 `rotate` / `revoke_all`。
//! `verify` 的威胁判定在 `tests/session.rs`。

use security_rust::session::{
    Decision, MemoryStore, RequestContext, SessionConfig, SessionGuard, SessionThreat,
};

const NOW: u64 = 1_000_000;
const FP: &str = "ip=1.2.3.4|ua=curl";

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

// ── bind ────────────────────────────────────────────────────

#[test]
fn bind_first_login_from_new_region_is_allowed() {
    // 没有任何历史时无法判定异地，必须放行 —— 否则所有新用户首登都被拦
    let g = guard();
    let v = g.bind(&ctx("t1", "u1", FP), NOW).unwrap();
    assert!(v.is_allowed());
    assert!(v.threats.is_empty());
}

#[test]
fn bind_from_different_region_than_history_challenges() {
    let g = guard();
    g.bind(&ctx("t1", "u1", FP), NOW).unwrap();

    let mut c = ctx("t2", "u1", FP);
    c.location = Some("US-NY");
    c.coords = None;
    let v = g.bind(&c, NOW + 86_400).unwrap();

    assert_eq!(v.decision, Decision::Challenge);
    assert!(v.threats.contains(&SessionThreat::LocationChanged));
}

#[test]
fn bind_same_region_case_insensitive_is_allowed() {
    let g = guard();
    g.bind(&ctx("t1", "u1", FP), NOW).unwrap();

    let mut c = ctx("t2", "u1", FP);
    c.location = Some("cn-bj");
    let v = g.bind(&c, NOW + 86_400).unwrap();
    assert!(v.is_allowed(), "大小写差异不该报异地: {:?}", v.threats);
}

#[test]
fn bind_impossible_travel_blocks() {
    let g = guard();
    g.bind(&ctx("t1", "u1", FP), NOW).unwrap(); // 北京

    let mut c = ctx("t2", "u1", FP);
    c.location = Some("US-NY");
    c.coords = Some((40.7128, -74.0060));
    // 1 小时后出现在纽约
    let v = g.bind(&c, NOW + 3_600).unwrap();

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
fn bind_does_not_compare_against_its_own_login_point() {
    // 同一位置连登两次：第二次的判断依据必须是历史，不是刚写入的本次记录
    let g = guard();
    g.bind(&ctx("t1", "u1", FP), NOW).unwrap();
    let v = g.bind(&ctx("t2", "u1", FP), NOW + 60).unwrap();
    assert!(v.is_allowed(), "同地登录误报: {:?}", v.threats);
}

#[test]
fn bind_rejects_empty_token() {
    let g = guard();
    assert_eq!(
        g.bind(&ctx("", "u1", FP), NOW).unwrap_err(),
        security_rust::session::SessionError::EmptyToken
    );
}

#[test]
fn bind_rejects_empty_subject() {
    let g = guard();
    assert_eq!(
        g.bind(&ctx("t1", "", FP), NOW).unwrap_err(),
        security_rust::session::SessionError::EmptySubject
    );
}

#[test]
fn bind_rejects_empty_fingerprint() {
    let g = guard();
    assert_eq!(
        g.bind(&ctx("t1", "u1", ""), NOW).unwrap_err(),
        security_rust::session::SessionError::EmptyFingerprint
    );
}

// ── revoke_all ──────────────────────────────────────────────

#[test]
fn revoke_all_kills_every_session_of_subject() {
    let g = guard();
    g.bind(&ctx("t1", "u1", FP), NOW).unwrap();
    g.bind(&ctx("t2", "u1", FP), NOW).unwrap();
    g.bind(&ctx("t3", "u2", "fp2"), NOW).unwrap();

    assert_eq!(g.revoke_all("u1").unwrap(), 2);

    assert_eq!(
        g.verify(&ctx("t1", "u1", FP), NOW + 10).threats,
        vec![SessionThreat::TokenRevoked]
    );
    assert_eq!(
        g.verify(&ctx("t2", "u1", FP), NOW + 10).threats,
        vec![SessionThreat::TokenRevoked]
    );
    // 别的用户不受影响
    assert!(g.verify(&ctx("t3", "u2", "fp2"), NOW + 10).is_allowed());
}

// ── rotate ──────────────────────────────────────────────────

#[test]
fn rotate_rejects_unknown_old_token() {
    let g = guard();
    assert_eq!(
        g.rotate("ghost", "new", &ctx("ghost", "u1", FP), NOW)
            .unwrap_err(),
        security_rust::session::SessionError::UnknownSession
    );
}

#[test]
fn rotate_rejects_expired_old_token() {
    let g = guard();
    g.bind(&ctx("old", "u1", FP), NOW).unwrap();
    assert_eq!(
        g.rotate("old", "new", &ctx("old", "u1", FP), NOW + 3_601)
            .unwrap_err(),
        security_rust::session::SessionError::UnknownSession
    );
}

#[test]
fn rotate_rejects_revoked_old_token() {
    let g = guard();
    g.bind(&ctx("old", "u1", FP), NOW).unwrap();
    g.revoke("old").unwrap();
    assert_eq!(
        g.rotate("old", "new", &ctx("old", "u1", FP), NOW + 10)
            .unwrap_err(),
        security_rust::session::SessionError::UnknownSession
    );
}

#[test]
fn rotate_rejects_empty_new_token() {
    let g = guard();
    g.bind(&ctx("old", "u1", FP), NOW).unwrap();
    assert_eq!(
        g.rotate("old", "", &ctx("old", "u1", FP), NOW + 10)
            .unwrap_err(),
        security_rust::session::SessionError::EmptyToken
    );
}

#[test]
fn rotate_rejects_fingerprint_mismatch() {
    // 拿别人的 token 换取新 token 必须失败，否则是提权漏洞
    let g = guard();
    g.bind(&ctx("old", "u1", FP), NOW).unwrap();
    assert_eq!(
        g.rotate("old", "new", &ctx("old", "u1", "ATTACKER"), NOW + 10)
            .unwrap_err(),
        security_rust::session::SessionError::UnknownSession
    );
}

// ── 端到端 ──────────────────────────────────────────────────

#[test]
fn full_session_lifecycle() {
    let g = SessionGuard::new(MemoryStore::new(), SessionConfig::default());

    // 1. 登录
    let v = g.bind(&ctx("tok-1", "alice", FP), NOW).unwrap();
    assert!(v.is_allowed());

    // 2. 正常请求
    let ok = g.verify(&ctx("tok-1", "alice", FP), NOW + 60);
    assert!(ok.is_allowed(), "误报: {:?}", ok.threats);

    // 3. 换设备 → 劫持
    let hijack = g.verify(&ctx("tok-1", "alice", "ip=9.9.9.9|ua=evil"), NOW + 120);
    assert_eq!(hijack.decision, Decision::Block);
    assert!(hijack.threats.contains(&SessionThreat::FingerprintMismatch));

    // 4. 续期
    g.rotate("tok-1", "tok-2", &ctx("tok-1", "alice", FP), NOW + 180)
        .unwrap();
    assert_eq!(
        g.verify(&ctx("tok-1", "alice", FP), NOW + 240).threats,
        vec![SessionThreat::TokenRevoked]
    );
    assert!(g.verify(&ctx("tok-2", "alice", FP), NOW + 240).is_allowed());

    // 5. 改密码 → 全部踢下线
    assert_eq!(g.revoke_all("alice").unwrap(), 1);
    assert_eq!(
        g.verify(&ctx("tok-2", "alice", FP), NOW + 300).threats,
        vec![SessionThreat::TokenRevoked]
    );
}
