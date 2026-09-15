// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use super::geo;
use super::store::{LoginPoint, SessionRecord, SessionStore};
use super::{
    RequestContext, SessionConfig, SessionError, SessionThreat, SessionVerdict, StoreError,
};

pub struct SessionGuard<S: SessionStore> {
    store: S,
    config: SessionConfig,
}

impl<S: SessionStore> SessionGuard<S> {
    pub fn new(store: S, config: SessionConfig) -> Self {
        Self { store, config }
    }

    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// 登录：建会话 + 绑指纹 + 记位置，并返回异地判定。
    ///
    /// 登录本身总是成功（除非调用方误用或后端故障）—— 异地只影响 verdict，
    /// 由调用方决定是否走二次验证，不应阻断登录。
    pub fn bind(&self, ctx: &RequestContext, now: u64) -> Result<SessionVerdict, SessionError> {
        if ctx.token.is_empty() {
            return Err(SessionError::EmptyToken);
        }
        if ctx.subject.is_empty() {
            return Err(SessionError::EmptySubject);
        }
        if ctx.fingerprint.is_empty() {
            return Err(SessionError::EmptyFingerprint);
        }

        // 坐标在信任边界校验一次：NaN / 越界一律降级为「没有坐标」，
        // 后面写入记录与登录历史的一律是这个清洗过的值
        let coords = geo::sanitize_coords(ctx.coords);

        let point = LoginPoint {
            location: ctx.location.map(str::to_string),
            coords,
            at: now,
        };

        // 异地判定必须在写入本次登录点之前取历史，否则会拿自己跟自己比
        let history = self.store.recent_logins(ctx.subject)?;

        let mut threats = Vec::new();
        if let Some(prev) = history.last() {
            if geo::location_changed(prev.location.as_deref(), ctx.location) {
                threats.push(SessionThreat::LocationChanged);
            }
            if let Some(kmh) =
                geo::impossible_travel(prev, &point, self.config.impossible_travel_kmh)
            {
                threats.push(SessionThreat::ImpossibleTravel { kmh });
            }
        }

        self.store.put(SessionRecord {
            token: ctx.token.to_string(),
            subject: ctx.subject.to_string(),
            fingerprint: ctx.fingerprint.to_string(),
            location: ctx.location.map(str::to_string),
            coords,
            signature: ctx.signature.map(str::to_string),
            issued_at: now,
            last_seen: now,
            expires_at: now.saturating_add(self.config.ttl_secs),
            revoked: false,
        })?;
        self.store.record_login(ctx.subject, point)?;

        Ok(SessionVerdict::from_threats(threats))
    }

    /// 每请求校验。
    ///
    /// 返回 `SessionVerdict` 而非 `Result`：认证路径上「拒绝」是正常结果而非错误，
    /// 强制调用方在类型层面处理每一种拒绝。
    pub fn verify(&self, ctx: &RequestContext, now: u64) -> SessionVerdict {
        // ── 门槛检查：记录不存在或不可读时，后续检查没有基线可比，必须提前退出 ──
        if ctx.token.is_empty() {
            return SessionVerdict::single(SessionThreat::TokenUnknown);
        }

        let record = match self.store.get(ctx.token) {
            Ok(Some(r)) => r,
            Ok(None) => return SessionVerdict::single(SessionThreat::TokenUnknown),
            // fail-closed：后端故障时放行所有请求是一个可被攻击者主动触发的绕过
            Err(_) => return SessionVerdict::single(SessionThreat::StoreUnavailable),
        };

        if record.revoked {
            return SessionVerdict::single(SessionThreat::TokenRevoked);
        }
        if record.expires_at <= now {
            return SessionVerdict::single(SessionThreat::TokenExpired);
        }

        self.verify_binding(ctx, &record, now)
    }

    /// 累积检查：需要有效基线，逐项收集而非提前退出，以便日志与取证完整。
    fn verify_binding(
        &self,
        ctx: &RequestContext,
        record: &SessionRecord,
        now: u64,
    ) -> SessionVerdict {
        let mut threats = Vec::new();

        // 劫持：指纹不符
        if !ct_eq(record.fingerprint.as_bytes(), ctx.fingerprint.as_bytes()) {
            threats.push(SessionThreat::FingerprintMismatch);
        }

        // 篡改：签名比对
        match (record.signature.as_deref(), ctx.signature) {
            (Some(stored), Some(current)) if !ct_eq(stored.as_bytes(), current.as_bytes()) => {
                threats.push(SessionThreat::SignatureInvalid);
            }
            (Some(_), None) => threats.push(SessionThreat::SignatureMissing),
            // 登录时没设基线，本次却带了签名：请求方与会话建立方行为不一致
            (None, Some(_)) => threats.push(SessionThreat::SignatureUnexpected),
            _ => {}
        }

        // 重放：请求自称时间偏离窗口
        if let Some(at) = ctx.at {
            if now.abs_diff(at) > self.config.timestamp_skew_secs {
                threats.push(SessionThreat::TimestampSkew);
            }
        }

        // 异地：与会话记录的位置比对
        if geo::location_changed(record.location.as_deref(), ctx.location) {
            threats.push(SessionThreat::LocationChanged);
        }

        // 异地（铁证）：与该身份的登录历史比对
        match self.store.recent_logins(&record.subject) {
            Ok(history) => {
                let current = LoginPoint {
                    location: ctx.location.map(str::to_string),
                    coords: geo::sanitize_coords(ctx.coords),
                    at: now,
                };
                if let Some(prev) = history.last() {
                    if let Some(kmh) =
                        geo::impossible_travel(prev, &current, self.config.impossible_travel_kmh)
                    {
                        threats.push(SessionThreat::ImpossibleTravel { kmh });
                    }
                }
            }
            // fail-closed：历史读不到时静默跳过，等于「后端一坏，异地检测就关」，
            // 攻击者可以用后端故障（或诱导故障）换掉一整类判定。上报为
            // StoreUnavailable（⇒ Block），与 bind() 对同一调用用 `?`、
            // verify() 把 get 的 Err 转 StoreUnavailable 的处置保持一致。
            Err(_) => threats.push(SessionThreat::StoreUnavailable),
        }

        if threats.is_empty() {
            // 只有放行时才刷新活跃度：被拦的请求不该延长会话寿命
            let _ = self.store.touch(ctx.token, now);
            return SessionVerdict::allow();
        }

        SessionVerdict::from_threats(threats)
    }

    /// 吊销单个会话（登出）。
    pub fn revoke(&self, token: &str) -> Result<(), StoreError> {
        self.store.revoke(token)
    }

    /// 吊销某 subject 的全部会话（改密码 / 踢下线），返回受影响条数。
    pub fn revoke_all(&self, subject: &str) -> Result<usize, StoreError> {
        self.store.revoke_subject(subject)
    }

    /// 续期换 token：旧 token 吊销，新 token 由调用方提供。
    ///
    /// 旧会话必须存在、未吊销、未过期，**且指纹与本次 ctx 相符** ——
    /// 否则等于允许攻击者拿别人的 token 换一个自己的新 token，是提权漏洞。
    ///
    /// 新记录的身份字段（subject / location / coords / signature）一律
    /// 以服务端记录为准，不接受 `ctx` 覆盖。
    pub fn rotate(
        &self,
        old: &str,
        new: &str,
        ctx: &RequestContext,
        now: u64,
    ) -> Result<(), SessionError> {
        if old.is_empty() || new.is_empty() {
            return Err(SessionError::EmptyToken);
        }

        let record = match self.store.get(old)? {
            Some(r) if !r.revoked && r.expires_at > now => r,
            _ => return Err(SessionError::UnknownSession),
        };

        if !ct_eq(record.fingerprint.as_bytes(), ctx.fingerprint.as_bytes()) {
            return Err(SessionError::UnknownSession);
        }

        self.store.put(SessionRecord {
            token: new.to_string(),
            issued_at: now,
            last_seen: now,
            expires_at: now.saturating_add(self.config.ttl_secs),
            revoked: false,
            ..record
        })?;
        // 旧 token 立即失效
        self.store.revoke(old)?;

        Ok(())
    }
}

/// 常数时间字节比较。
///
/// 用于比对 MAC / 指纹 —— 直接用 `==` 比较会在首个不同字节处提前返回，
/// 泄露「前 N 个字节猜对了」的时序信息。
///
/// 长度不同立即返回 `false`：长度会泄露，但长度本身不敏感，这是通行做法。
/// `black_box` 阻止优化器把累积循环改写成提前退出。
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::super::store::MemoryStore;
    use super::super::Decision;
    use super::*;

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

    // 这些测试要读 `guard.store` 的私有字段，因此留在单测里；
    // 纯公开 API 的行为测试（含 fail-closed、误报防护）在 tests/session*.rs。

    #[test]
    fn ct_eq_equal() {
        assert!(ct_eq(b"abc123", b"abc123"));
    }

    #[test]
    fn ct_eq_empty_is_equal() {
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn ct_eq_single_byte_difference() {
        assert!(!ct_eq(b"abc123", b"abc124"));
        // 首字节不同
        assert!(!ct_eq(b"abc123", b"zbc123"));
    }

    #[test]
    fn ct_eq_long_common_prefix_still_differs() {
        let a = vec![7u8; 4096];
        let mut b = a.clone();
        b[4095] = 8;
        assert!(!ct_eq(&a, &b));
    }

    #[test]
    fn ct_eq_length_mismatch() {
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(!ct_eq(b"", b"a"));
    }

    #[test]
    fn ct_eq_non_ascii_bytes() {
        assert!(ct_eq("签名".as_bytes(), "签名".as_bytes()));
        assert!(!ct_eq("签名".as_bytes(), "签名!".as_bytes()));
    }

    #[test]
    fn ct_eq_differs_only_in_last_byte_of_each_length() {
        // 累积或运算保证：即使差异出现在末尾也返回 false，不会被优化成提前退出
        for len in [1usize, 2, 3, 16, 32, 256] {
            let a = vec![0u8; len];
            let mut b = a.clone();
            b[len - 1] = 1;
            assert!(!ct_eq(&a, &b), "len {len}");
        }
    }

    #[test]
    fn guard_is_generic_over_store() {
        // SessionGuard 只绑定 SessionStore trait，便于多实例部署换后端
        let g = SessionGuard::new(MemoryStore::new(), SessionConfig::default());
        assert_eq!(g.config().ttl_secs, 3600);
        assert_eq!(g.config().impossible_travel_kmh, 900.0);
        assert_eq!(g.config().timestamp_skew_secs, 300);
    }

    #[test]
    fn bind_creates_session_record() {
        let g = guard();
        let v = g.bind(&ctx("t1", "u1", FP), NOW).unwrap();
        assert!(v.is_allowed(), "首登无历史，不该报异地: {:?}", v.threats);
        let r = g.store.get("t1").unwrap().expect("record created");
        assert_eq!(r.subject, "u1");
        assert_eq!(r.fingerprint, FP);
        assert_eq!(r.issued_at, NOW);
        assert_eq!(r.last_seen, NOW);
        assert_eq!(r.expires_at, NOW + 3600);
        assert!(!r.revoked);
    }

    #[test]
    fn bind_records_login_point() {
        let g = guard();
        g.bind(&ctx("t1", "u1", FP), NOW).unwrap();
        let h = g.store.recent_logins("u1").unwrap();
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].location.as_deref(), Some("CN-BJ"));
        assert_eq!(h[0].at, NOW);
    }

    #[test]
    fn bind_drops_non_finite_coords_at_trust_boundary() {
        // NaN 一旦入库/入历史就会长期污染该 subject 的异地判定，必须在入口清洗
        let g = guard();
        let mut bad = ctx("t1", "u1", FP);
        bad.coords = Some((f64::NAN, 116.4074));
        g.bind(&bad, NOW).unwrap();
        assert_eq!(g.store.get("t1").unwrap().unwrap().coords, None);
        assert_eq!(g.store.recent_logins("u1").unwrap()[0].coords, None);

        // 合法坐标照常保留
        let mut good = ctx("t2", "u2", FP);
        good.coords = Some((31.2304, 121.4737));
        g.bind(&good, NOW).unwrap();
        assert_eq!(
            g.store.get("t2").unwrap().unwrap().coords,
            Some((31.2304, 121.4737))
        );
    }

    #[test]
    fn bind_stores_signature_baseline() {
        let g = guard();
        let mut c = ctx("t1", "u1", FP);
        c.signature = Some("mac-abc");
        g.bind(&c, NOW).unwrap();
        assert_eq!(
            g.store.get("t1").unwrap().unwrap().signature.as_deref(),
            Some("mac-abc")
        );
    }

    #[test]
    fn bind_honours_custom_ttl() {
        let g = SessionGuard::new(
            MemoryStore::new(),
            SessionConfig {
                ttl_secs: 60,
                ..Default::default()
            },
        );
        g.bind(&ctx("t1", "u1", FP), NOW).unwrap();
        assert_eq!(g.store.get("t1").unwrap().unwrap().expires_at, NOW + 60);
    }

    #[test]
    fn verify_refreshes_last_seen_only_when_allowed() {
        let g = guard();
        g.bind(&ctx("t1", "u1", FP), NOW).unwrap();
        assert!(g.verify(&ctx("t1", "u1", FP), NOW + 10).is_allowed());
        assert_eq!(g.store.get("t1").unwrap().unwrap().last_seen, NOW + 10);
    }

    #[test]
    fn verify_does_not_refresh_last_seen_when_blocked() {
        let g = guard();
        g.bind(&ctx("t1", "u1", FP), NOW).unwrap();
        let v = g.verify(&ctx("t1", "u1", "ATTACKER-FP"), NOW + 10);
        assert_eq!(v.decision, Decision::Block);
        assert_eq!(
            g.store.get("t1").unwrap().unwrap().last_seen,
            NOW,
            "被拦的请求不该延长会话寿命"
        );
    }

    #[test]
    fn rotate_issues_new_token_and_kills_old() {
        let g = guard();
        g.bind(&ctx("old", "u1", FP), NOW).unwrap();
        g.rotate("old", "new", &ctx("old", "u1", FP), NOW + 10)
            .unwrap();

        assert_eq!(
            g.verify(&ctx("old", "u1", FP), NOW + 20).threats,
            vec![SessionThreat::TokenRevoked]
        );
        // 新 token 可用，且继承 subject / 指纹 / 位置基线
        let v = g.verify(&ctx("new", "u1", FP), NOW + 20);
        assert!(v.is_allowed(), "got {:?}", v.threats);
        let r = g.store.get("new").unwrap().unwrap();
        assert_eq!(r.subject, "u1");
        assert_eq!(r.fingerprint, FP);
        assert_eq!(r.location.as_deref(), Some("CN-BJ"));
    }

    #[test]
    fn rotate_refreshes_ttl() {
        let g = guard();
        g.bind(&ctx("old", "u1", FP), NOW).unwrap();
        g.rotate("old", "new", &ctx("old", "u1", FP), NOW + 1_000)
            .unwrap();
        assert_eq!(
            g.store.get("new").unwrap().unwrap().expires_at,
            NOW + 1_000 + 3_600
        );
    }

    #[test]
    fn rotate_ignores_ctx_subject_and_uses_record_subject() {
        // subject 以服务端记录为准，不能被请求方覆盖
        let g = guard();
        g.bind(&ctx("old", "u1", FP), NOW).unwrap();
        g.rotate("old", "new", &ctx("old", "VICTIM", FP), NOW + 10)
            .unwrap();
        assert_eq!(g.store.get("new").unwrap().unwrap().subject, "u1");
    }
}
