// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use super::StoreError;
use std::collections::HashMap;
use std::sync::Mutex;

/// 会话记录 —— 这张表就是「token 会话」。
#[derive(Debug, Clone, PartialEq)]
pub struct SessionRecord {
    pub token: String,
    pub subject: String,
    pub fingerprint: String,
    pub location: Option<String>,
    pub coords: Option<(f64, f64)>,
    /// 登录时的签名基线。
    pub signature: Option<String>,
    pub issued_at: u64,
    pub last_seen: u64,
    pub expires_at: u64,
    pub revoked: bool,
}

/// 一次登录的位置快照，用于异地检测与不可能旅行。
#[derive(Debug, Clone, PartialEq)]
pub struct LoginPoint {
    pub location: Option<String>,
    pub coords: Option<(f64, f64)>,
    pub at: u64,
}

pub trait SessionStore: Send + Sync {
    fn put(&self, rec: SessionRecord) -> Result<(), StoreError>;
    /// 原样返回记录，**不过滤过期**。过期判定归 `guard` ——
    /// 若此处对过期记录返回 `None`，`verify` 将无法区分 `TokenExpired` 与 `TokenUnknown`。
    fn get(&self, token: &str) -> Result<Option<SessionRecord>, StoreError>;
    fn touch(&self, token: &str, now: u64) -> Result<(), StoreError>;
    fn revoke(&self, token: &str) -> Result<(), StoreError>;
    /// 吊销某 subject 的全部会话，返回受影响条数。
    fn revoke_subject(&self, subject: &str) -> Result<usize, StoreError>;
    /// 该 subject 的登录历史，按时间升序（最旧在前）。
    fn recent_logins(&self, subject: &str) -> Result<Vec<LoginPoint>, StoreError>;
    fn record_login(&self, subject: &str, point: LoginPoint) -> Result<(), StoreError>;
    /// 清除已过期记录，并回收超过 [`LOGIN_HISTORY_KEEP_SECS`] 未再登录的
    /// subject 的登录历史；返回清除的会话条数。
    fn purge_expired(&self, now: u64) -> Result<usize, StoreError>;
}

/// 每个 subject 保留的登录历史条数上限。
pub const MAX_LOGINS_PER_SUBJECT: usize = 10;

/// 登录历史的保留时长（秒）：超过这段时间没有新登录点的 subject，
/// 其登录历史会在 [`SessionStore::purge_expired`] 时整条删除。
///
/// **取舍**：历史只在 `bind` / `verify` 里被读其中的 `last()` 一条，因此回收一个
/// 休眠 subject 的历史，代价是他的**下一次登录少做一次异地 / 不可能旅行判定**
/// （之后历史立即重建）。这是漏报而非误报——`location_changed` 缺输入返回
/// `false`、`impossible_travel` 缺输入返回 `None`，删掉输入只会让结论变成「不报」。
/// 这个常量就是旋钮：调大 = 更不容易漏报、内存占用更高。
///
/// 取 7 天是宽裕余量：地表最远两点约 20000 km，默认 900 km/h 阈值下不可能旅行
/// 判定在约 22 小时后本就不可能成立。单 subject 的历史条数由
/// [`MAX_LOGINS_PER_SUBJECT`] 限死，**无上限的是 subject 数量**，只能靠这个时间窗口回收。
pub const LOGIN_HISTORY_KEEP_SECS: u64 = 604_800;

/// 内存后端。无后台线程 —— 过期判定归 guard，内存回收靠 `purge_expired`。
#[derive(Debug)]
pub struct MemoryStore {
    sessions: Mutex<HashMap<String, SessionRecord>>,
    logins: Mutex<HashMap<String, Vec<LoginPoint>>>,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            logins: Mutex::new(HashMap::new()),
        }
    }

    /// 互斥锁获取。线程 panic 导致锁中毒时恢复内部数据而非永久 Err：
    /// 本 store 的每个操作都是单次 HashMap 读/写，不存在「改到一半」的不变量，
    /// 恢复是安全的；而让一次 panic 永久锁死整个会话存储是一种自我 DoS。
    fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        m.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl SessionStore for MemoryStore {
    fn put(&self, rec: SessionRecord) -> Result<(), StoreError> {
        Self::lock(&self.sessions).insert(rec.token.clone(), rec);
        Ok(())
    }

    fn get(&self, token: &str) -> Result<Option<SessionRecord>, StoreError> {
        Ok(Self::lock(&self.sessions).get(token).cloned())
    }

    fn touch(&self, token: &str, now: u64) -> Result<(), StoreError> {
        if let Some(r) = Self::lock(&self.sessions).get_mut(token) {
            r.last_seen = now;
        }
        Ok(())
    }

    fn revoke(&self, token: &str) -> Result<(), StoreError> {
        if let Some(r) = Self::lock(&self.sessions).get_mut(token) {
            r.revoked = true;
        }
        Ok(())
    }

    // ponytail: 持全局锁的 O(n) 全表扫描。内存后端规模下可接受；
    // 若单 subject 会话数上到万级或需跨实例，加 subject -> tokens 索引。
    fn revoke_subject(&self, subject: &str) -> Result<usize, StoreError> {
        let mut n = 0;
        for r in Self::lock(&self.sessions).values_mut() {
            if r.subject == subject && !r.revoked {
                r.revoked = true;
                n += 1;
            }
        }
        Ok(n)
    }

    fn recent_logins(&self, subject: &str) -> Result<Vec<LoginPoint>, StoreError> {
        Ok(Self::lock(&self.logins)
            .get(subject)
            .cloned()
            .unwrap_or_default())
    }

    fn record_login(&self, subject: &str, point: LoginPoint) -> Result<(), StoreError> {
        let mut g = Self::lock(&self.logins);
        let v = g.entry(subject.to_string()).or_default();
        v.push(point);
        // 有界：只保留最近 MAX_LOGINS_PER_SUBJECT 条
        if v.len() > MAX_LOGINS_PER_SUBJECT {
            v.drain(..v.len() - MAX_LOGINS_PER_SUBJECT);
        }
        Ok(())
    }

    fn purge_expired(&self, now: u64) -> Result<usize, StoreError> {
        let mut g = Self::lock(&self.sessions);
        let before = g.len();
        g.retain(|_, r| r.expires_at > now);
        let removed = before - g.len();
        drop(g);

        // 登录历史没有 expires_at 可依，按最后一个登录点的年龄回收。
        // 扫全量而非取 `v.last()`：`at` 只在时钟单调时才随插入递增，回拨会让
        // `last()` 指向更旧的点，把窗口内仍有效的历史整条丢掉。
        let horizon = now.saturating_sub(LOGIN_HISTORY_KEEP_SECS);
        Self::lock(&self.logins).retain(|_, v| v.iter().any(|p| p.at > horizon));
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(token: &str, subject: &str, expires_at: u64) -> SessionRecord {
        SessionRecord {
            token: token.into(),
            subject: subject.into(),
            fingerprint: "ip=1.2.3.4|ua=curl".into(),
            location: Some("CN-BJ".into()),
            coords: Some((39.9042, 116.4074)),
            signature: None,
            issued_at: 1_000,
            last_seen: 1_000,
            expires_at,
            revoked: false,
        }
    }

    #[test]
    fn put_then_get_roundtrip() {
        let s = MemoryStore::new();
        s.put(rec("t1", "u1", 2_000)).unwrap();
        let got = s.get("t1").unwrap().expect("present");
        assert_eq!(got.token, "t1");
        assert_eq!(got.subject, "u1");
    }

    #[test]
    fn get_unknown_token_is_none() {
        let s = MemoryStore::new();
        assert!(s.get("nope").unwrap().is_none());
    }

    #[test]
    fn get_returns_expired_record_unfiltered() {
        // 关键契约：store 不做过期过滤，过期判定归 guard。
        // 否则 verify 无法区分 TokenExpired 与 TokenUnknown。
        let s = MemoryStore::new();
        s.put(rec("t1", "u1", 500)).unwrap();
        let got = s.get("t1").unwrap().expect("must still be returned");
        assert_eq!(got.expires_at, 500);
    }

    #[test]
    fn touch_updates_last_seen_only() {
        let s = MemoryStore::new();
        s.put(rec("t1", "u1", 9_999)).unwrap();
        s.touch("t1", 1_500).unwrap();
        let got = s.get("t1").unwrap().unwrap();
        assert_eq!(got.last_seen, 1_500);
        assert_eq!(got.issued_at, 1_000);
        assert_eq!(got.expires_at, 9_999);
    }

    #[test]
    fn touch_unknown_token_is_ok() {
        let s = MemoryStore::new();
        assert!(s.touch("nope", 1_500).is_ok());
    }

    #[test]
    fn revoke_marks_record_not_deletes_it() {
        let s = MemoryStore::new();
        s.put(rec("t1", "u1", 9_999)).unwrap();
        s.revoke("t1").unwrap();
        let got = s.get("t1").unwrap().expect("kept for diagnosis");
        assert!(got.revoked);
    }

    #[test]
    fn revoke_unknown_token_is_ok() {
        let s = MemoryStore::new();
        assert!(s.revoke("nope").is_ok());
    }

    #[test]
    fn revoke_subject_counts_only_newly_revoked() {
        let s = MemoryStore::new();
        s.put(rec("t1", "u1", 9_999)).unwrap();
        s.put(rec("t2", "u1", 9_999)).unwrap();
        s.put(rec("t3", "u2", 9_999)).unwrap();
        assert_eq!(s.revoke_subject("u1").unwrap(), 2);
        // 再调一次不该重复计数
        assert_eq!(s.revoke_subject("u1").unwrap(), 0);
        assert!(!s.get("t3").unwrap().unwrap().revoked);
    }

    #[test]
    fn revoke_subject_unknown_is_zero() {
        let s = MemoryStore::new();
        assert_eq!(s.revoke_subject("ghost").unwrap(), 0);
    }

    fn point(loc: &str, at: u64) -> LoginPoint {
        LoginPoint {
            location: Some(loc.into()),
            coords: None,
            at,
        }
    }

    #[test]
    fn login_history_is_ascending() {
        let s = MemoryStore::new();
        s.record_login("u1", point("CN-BJ", 100)).unwrap();
        s.record_login("u1", point("CN-SH", 200)).unwrap();
        let h = s.recent_logins("u1").unwrap();
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].at, 100);
        assert_eq!(h[1].at, 200);
    }

    #[test]
    fn login_history_is_bounded() {
        let s = MemoryStore::new();
        for i in 0..(MAX_LOGINS_PER_SUBJECT as u64 + 5) {
            s.record_login("u1", point("CN-BJ", 100 + i)).unwrap();
        }
        let h = s.recent_logins("u1").unwrap();
        assert_eq!(h.len(), MAX_LOGINS_PER_SUBJECT);
        // 保留的是最近的：最旧的一条应为 at = 105
        assert_eq!(h[0].at, 105);
    }

    #[test]
    fn recent_logins_unknown_subject_is_empty() {
        let s = MemoryStore::new();
        assert!(s.recent_logins("ghost").unwrap().is_empty());
    }

    #[test]
    fn purge_expired_removes_only_expired() {
        let s = MemoryStore::new();
        s.put(rec("old", "u1", 500)).unwrap();
        s.put(rec("new", "u1", 5_000)).unwrap();
        assert_eq!(s.purge_expired(1_000).unwrap(), 1);
        assert!(s.get("old").unwrap().is_none());
        assert!(s.get("new").unwrap().is_some());
    }

    #[test]
    fn purge_expired_boundary_is_exclusive() {
        // expires_at == now 视为已过期
        let s = MemoryStore::new();
        s.put(rec("t", "u1", 1_000)).unwrap();
        assert_eq!(s.purge_expired(1_000).unwrap(), 1);
    }

    #[test]
    fn purge_expired_on_empty_is_zero() {
        let s = MemoryStore::new();
        assert_eq!(s.purge_expired(1_000).unwrap(), 0);
    }

    #[test]
    fn purge_expired_reclaims_dormant_login_history() {
        // 登录历史此前只增不减：凭据填充 / 换用户名爆破每个 subject 永久占一份条目。
        // 这里钉住回收路径 —— 没有它，purge_expired 对 logins 完全无效。
        let s = MemoryStore::new();
        let now = 10_000_000;
        let stale = now - LOGIN_HISTORY_KEEP_SECS;
        s.record_login("dormant", point("CN-BJ", stale - 1))
            .unwrap();
        // 窗口边界（恰好在 horizon 上）同样算休眠，与 sessions 的 `expires_at > now` 一致
        s.record_login("edge", point("CN-BJ", stale)).unwrap();
        s.record_login("active", point("CN-SH", now - 10)).unwrap();

        assert_eq!(s.purge_expired(now).unwrap(), 0, "无过期会话");

        assert!(s.recent_logins("dormant").unwrap().is_empty());
        assert!(s.recent_logins("edge").unwrap().is_empty());
        assert_eq!(s.recent_logins("active").unwrap().len(), 1);
        // 「删掉键」才算真的回收，空 Vec 仍会占住 map 条目
        assert_eq!(MemoryStore::lock(&s.logins).len(), 1);
    }

    #[test]
    fn purge_expired_keeps_history_after_clock_rollback() {
        let s = MemoryStore::new();
        let now = 10_000_000;
        // 时钟回拨：后写入的点 at 反而更小，`last()` 会指向窗口外的那条
        s.record_login("u1", point("CN-BJ", now - 10)).unwrap();
        s.record_login("u1", point("CN-BJ", now - 2 * LOGIN_HISTORY_KEEP_SECS))
            .unwrap();

        assert_eq!(s.purge_expired(now).unwrap(), 0);
        assert_eq!(
            s.recent_logins("u1").unwrap().len(),
            2,
            "取 last() 会把窗口内仍有效的历史整条丢掉"
        );
    }

    #[test]
    fn lock_recovers_from_poisoned_mutex() {
        // 钉住 lock() 的恢复不变量：一次 panic 不能永久锁死会话存储。
        let m = Mutex::new(rec("t1", "u1", 9_999));
        std::panic::catch_unwind(|| {
            let _guard = m.lock().unwrap();
            panic!("poison");
        })
        .unwrap_err();
        assert!(m.is_poisoned());

        let g = MemoryStore::lock(&m);
        assert_eq!(g.token, "t1");
        assert_eq!(g.expires_at, 9_999);
    }
}
