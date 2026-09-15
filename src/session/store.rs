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
    /// 清除已过期记录，返回清除条数。
    fn purge_expired(&self, now: u64) -> Result<usize, StoreError>;
}

/// 每个 subject 保留的登录历史条数上限。
pub const MAX_LOGINS_PER_SUBJECT: usize = 10;

/// 内存后端。无后台线程 —— 过期判定归 guard，内存回收靠 `purge_expired`。
#[derive(Debug)]
pub struct MemoryStore {
    sessions: Mutex<HashMap<String, SessionRecord>>,
    logins: Mutex<HashMap<String, Vec<LoginPoint>>>,
    max_logins: usize,
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
            max_logins: MAX_LOGINS_PER_SUBJECT,
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
        // 有界：只保留最近 max_logins 条
        if v.len() > self.max_logins {
            let excess = v.len() - self.max_logins;
            v.drain(..excess);
        }
        Ok(())
    }

    fn purge_expired(&self, now: u64) -> Result<usize, StoreError> {
        let mut g = Self::lock(&self.sessions);
        let before = g.len();
        g.retain(|_, r| r.expires_at > now);
        Ok(before - g.len())
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
}
