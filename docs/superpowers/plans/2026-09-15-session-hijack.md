<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# Session Security Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 新增 `src/session/` 模块，实现客户端劫持检测、数据篡改检测、异地登录检测与 token 会话管理。

**Architecture:** 独立于现有 `Detector` 体系的有状态模块。`SessionStore` trait 抽象会话存储（自带 `MemoryStore`），`SessionGuard` 承载 bind/verify/revoke/rotate 生命周期，`geo` 提供纯函数地理计算。零新依赖，依赖表保持只有 `regex`。

**Tech Stack:** Rust 2024（rust-version 1.87）、std 独占（`Mutex`/`HashMap`/`f64` 数学）、`regex` 仅用于既有模块。

**Spec:** `docs/superpowers/specs/2026-09-15-session-hijack-design.md`

---

## 对 spec 的两处偏离（实现前须知）

1. **`SessionError` 增加第 5 个变体 `UnknownSession`。** spec 只列了 4 个变体，但 `rotate(old, new, ..)` 在旧 token 不存在时必须能报错，且不能复用 `EmptyToken`（语义不对）。Task 9 实现之。
2. **spec 的 `MemoryStore::get` 行为已修正**（见 spec 该节）：`get` 原样返回记录不过滤过期，过期判定归 `guard`。否则 `TokenExpired` 与 `TokenUnknown` 无法区分。

## File Structure

| 文件 | 职责 | 状态 |
|---|---|---|
| `src/result.rs` | `Severity` 增加 `PartialOrd, Ord` 派生 | 改（1 行） |
| `src/lib.rs` | 挂载 `pub mod session;` + re-export | 改 |
| `src/session/mod.rs` | 共享词汇类型：`Decision` / `SessionThreat` / `SessionVerdict` / `RequestContext` / `SessionConfig` / `StoreError` / `SessionError` | 建 |
| `src/session/geo.rs` | `haversine_km` / `location_changed` / `impossible_travel`，纯函数无状态 | 建 |
| `src/session/store.rs` | `SessionRecord` / `LoginPoint` / `SessionStore` trait / `MemoryStore` | 建 |
| `src/session/guard.rs` | `SessionGuard` + `ct_eq` | 建 |
| `tests/session.rs` | 集成测试（fail-closed、端到端、可插拔存储） | 建 |
| `README.md` / `docs/API.md` | 新模块文档 | 改 |

**类型归属约定**：`mod.rs` 放「store 与 guard 都要说的词汇」；`store.rs` 放存储自身的数据形状；`guard.rs` 只放行为。这样 `geo` 与 `store` 都不依赖 `guard`。

---

### Task 1: 基础设施 — `Severity` 排序 + 模块骨架

**Files:**
- Modify: `src/result.rs:5-11`
- Modify: `src/lib.rs:5-13`
- Create: `src/session/mod.rs`

- [ ] **Step 1: 给 `Severity` 加序**

`src/result.rs` 第 5 行，改派生：

```rust
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}
```

**注意**：声明顺序决定 `Ord` 顺序，`Critical` 最小。因此「取最高严重度」不能用 `max()`。为免误用，不依赖 `Ord` 比较 `Severity`，改为在 `mod.rs` 中显式定义排序权重（Task 3 的 `severity_rank`）。这里加 `Ord` 只为让 `Severity` 可排序。

- [ ] **Step 2: 写测试验证派生生效并记录陷阱**

在 `src/result.rs` 的 `mod tests` 末尾追加：

```rust
    #[test]
    fn severity_ordering_is_declaration_order() {
        // 声明顺序：Critical < High < Medium < Low
        assert!(Severity::Critical < Severity::High);
        assert!(Severity::High < Severity::Medium);
        assert!(Severity::Medium < Severity::Low);
    }

    #[test]
    fn severity_max_is_the_least_severe() {
        // 陷阱记录：Ord 顺序与"严重程度"相反，故不能用 max() 取最严重
        assert_eq!(Severity::Critical.max(Severity::Low), Severity::Low);
    }
```

- [ ] **Step 3: 运行测试**

Run: `cargo test --lib result::`
Expected: PASS（含既有 6 个 result 测试）

- [ ] **Step 4: 建模块骨架并挂载**

创建 `src/session/mod.rs`：

```rust
// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

pub mod geo;
pub mod guard;
pub mod store;
```

`src/lib.rs` 第 5-10 行的 `pub mod` 区块追加一行：

```rust
pub mod session;
```

**此处不加 `pub use` 重导出** —— 重导出列表引用的类型此刻都还不存在，会让 `cargo build` 直接失败。重导出留到 Task 10 类型齐全时再加。

- [ ] **Step 5: 建三个空子模块**

`src/session/geo.rs`、`src/session/store.rs`、`src/session/guard.rs` 各建为空文件（仅版权头）。

- [ ] **Step 6: 验证编译**

Run: `cargo build`
Expected: 编译成功，无警告

- [ ] **Step 7: 提交**

```bash
git add src/result.rs src/lib.rs src/session/
git commit -m "feat(session): 挂载 session 模块骨架，Severity 增加 Ord 派生"
```

---

### Task 2: 存储层 — `store.rs` 的类型、trait 与 `MemoryStore`

**Files:**
- Modify: `src/session/store.rs`
- Test: `src/session/store.rs`

> **与 Task 3 一起完成**：本文件依赖 Task 3 定义的 `StoreError`，而 Task 3 的 `mod.rs` 又依赖本文件的 `MemoryStore` / `SessionStore`。按 Task 2 Step 1 → Task 3 Step 1 的顺序把两侧代码都写完，再跑测试；提交放在 Task 3 末尾。
> 本任务先于 `geo` 做，因为 `geo` 的 `impossible_travel` 依赖 `LoginPoint`。

- [ ] **Step 1: 写测试与实现**

写入 `src/session/store.rs`：

```rust
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
```

- [ ] **Step 2: 运行测试**

**前置**：`use super::StoreError;` 需要 Task 3 Step 1 已写好。

Run: `cargo test --lib session::store::`
Expected: 15 个测试全部 PASS

---

### Task 3: 词汇层 — `session/mod.rs` 的共享类型

**Files:**
- Modify: `src/session/mod.rs`
- Test: `src/session/mod.rs`

> 与 Task 2 一起完成，见 Task 2 开头的说明。

- [ ] **Step 1: 写类型**

在 `src/session/mod.rs` 的 `pub mod` 声明之后追加：

```rust
use crate::Severity;

pub use guard::SessionGuard;
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
```

- [ ] **Step 2: 注释掉 re-export**

`pub use guard::SessionGuard;` 引用的 `guard.rs` 此时还是空文件，会让编译失败。暂时注释该行，Task 5 恢复。

- [ ] **Step 3: 写测试**

在 `src/session/mod.rs` 末尾追加：

```rust
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
            SessionThreat::LocationChanged,    // Challenge
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
```

- [ ] **Step 4: 运行测试**

Run: `cargo test --lib session::tests::`
Expected: 11 个测试全部 PASS

- [ ] **Step 5: 提交**

```bash
git add src/session/mod.rs src/session/store.rs
git commit -m "feat(session): 共享词汇类型与 SessionStore/MemoryStore"
```

---

### Task 4: `geo.rs` — 纯函数地理计算

**Files:**
- Modify: `src/session/geo.rs`
- Test: `src/session/geo.rs`

- [ ] **Step 1: 写测试与实现**

写入 `src/session/geo.rs`：

```rust
// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use super::store::LoginPoint;

/// 地球平均半径（km），IUGG 均值。
const EARTH_RADIUS_KM: f64 = 6371.0088;

/// 两点大圆距离（km）。坐标均为 (纬度, 经度) 十进制度。
///
/// 用 atan2 形式而非 asin 形式：asin 在两点接近时对浮点误差敏感，
/// atan2 形式在整个定义域上数值稳定。
pub(crate) fn haversine_km(a: (f64, f64), b: (f64, f64)) -> f64 {
    let (lat1, lon1) = (a.0.to_radians(), a.1.to_radians());
    let (lat2, lon2) = (b.0.to_radians(), b.1.to_radians());
    let dlat = lat2 - lat1;
    let dlon = lon2 - lon1;
    let h = (dlat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (dlon / 2.0).sin().powi(2);
    // h 理论上属 [0,1]，浮点误差可能略微越界，clamp 防止 sqrt 出 NaN
    let h = h.clamp(0.0, 1.0);
    2.0 * EARTH_RADIUS_KM * h.sqrt().atan2((1.0 - h).sqrt())
}

/// 区域标识是否变化。大小写不敏感并去除首尾空白，
/// 避免调用方给的 "CN-BJ" / " cn-bj " 被误判为两地。
///
/// 任一侧为 `None` 时返回 `false`（无法判定，不报）—— 调用方可能只在
/// 部分请求上提供位置信息，缺失不应产生误报。
pub(crate) fn location_changed(recorded: Option<&str>, current: Option<&str>) -> bool {
    match (recorded, current) {
        (Some(a), Some(b)) => !a.trim().eq_ignore_ascii_case(b.trim()),
        _ => false,
    }
}

/// 判断这次登录相对上一条记录是否属于「不可能旅行」。
///
/// 返回隐含速度（km/h）当且仅当它超过 `max_kmh`；否则返回 `None`。
/// 缺少任一侧坐标、或时间未前进时返回 `None`（不判定）。
pub(crate) fn impossible_travel(prev: &LoginPoint, cur: &LoginPoint, max_kmh: f64) -> Option<f64> {
    let (a, b) = (prev.coords?, cur.coords?);
    // 时间未前进（含相等）：无法计算速度，交给其它检查项
    if cur.at <= prev.at {
        return None;
    }
    let hours = (cur.at - prev.at) as f64 / 3600.0;
    let kmh = haversine_km(a, b) / hours;
    (kmh > max_kmh).then_some(kmh)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BEIJING: (f64, f64) = (39.9042, 116.4074);
    const NEW_YORK: (f64, f64) = (40.7128, -74.0060);
    const SHANGHAI: (f64, f64) = (31.2304, 121.4737);

    fn point(coords: Option<(f64, f64)>, at: u64) -> LoginPoint {
        LoginPoint {
            location: None,
            coords,
            at,
        }
    }

    #[test]
    fn haversine_zero_distance() {
        assert!(haversine_km(BEIJING, BEIJING) < 0.001);
    }

    #[test]
    fn haversine_beijing_to_new_york() {
        // 大圆距离约 11000 km，放宽到 ±500 容忍半径取值差异
        let km = haversine_km(BEIJING, NEW_YORK);
        assert!((10_500.0..11_500.0).contains(&km), "got {km}");
    }

    #[test]
    fn haversine_beijing_to_shanghai() {
        // 约 1067 km
        let km = haversine_km(BEIJING, SHANGHAI);
        assert!((1_000.0..1_150.0).contains(&km), "got {km}");
    }

    #[test]
    fn haversine_is_symmetric() {
        let a = haversine_km(BEIJING, NEW_YORK);
        let b = haversine_km(NEW_YORK, BEIJING);
        assert!((a - b).abs() < 1e-9);
    }

    #[test]
    fn location_changed_detects_different_region() {
        assert!(location_changed(Some("CN-BJ"), Some("US-NY")));
    }

    #[test]
    fn location_changed_ignores_case_and_whitespace() {
        assert!(!location_changed(Some("CN-BJ"), Some("cn-bj")));
        assert!(!location_changed(Some("cn-bj"), Some("  CN-BJ  ")));
    }

    #[test]
    fn location_changed_false_when_either_side_missing() {
        assert!(!location_changed(None, Some("CN-BJ")));
        assert!(!location_changed(Some("CN-BJ"), None));
        assert!(!location_changed(None, None));
    }

    #[test]
    fn impossible_travel_flags_unrealistic_speed() {
        // 北京→纽约 11000km 在 1 小时内：11000 km/h >> 900
        let prev = point(Some(BEIJING), 1_000);
        let cur = point(Some(NEW_YORK), 1_000 + 3600);
        let kmh = impossible_travel(&prev, &cur, 900.0).expect("should be impossible");
        assert!(kmh > 10_000.0, "got {kmh}");
    }

    #[test]
    fn impossible_travel_allows_realistic_flight() {
        // 北京→纽约 11000km 用 14 小时：约 786 km/h < 900
        let prev = point(Some(BEIJING), 1_000);
        let cur = point(Some(NEW_YORK), 1_000 + 14 * 3600);
        assert!(impossible_travel(&prev, &cur, 900.0).is_none());
    }

    #[test]
    fn impossible_travel_threshold_boundary() {
        // 同经度上纬差 0.054 度约 6km，30 秒内约 720 km/h，低于 900 不报
        let prev = point(Some((39.9042, 116.4074)), 1_000);
        let cur = point(Some((39.9582, 116.4074)), 1_030);
        assert!(impossible_travel(&prev, &cur, 900.0).is_none());
        // 同一对点在更低阈值下应触发
        assert!(impossible_travel(&prev, &cur, 500.0).is_some());
    }

    #[test]
    fn impossible_travel_none_without_coords() {
        let prev = point(None, 1_000);
        let cur = point(Some(NEW_YORK), 1_000 + 60);
        assert!(impossible_travel(&prev, &cur, 900.0).is_none());
        let prev2 = point(Some(BEIJING), 1_000);
        let cur2 = point(None, 1_000 + 60);
        assert!(impossible_travel(&prev2, &cur2, 900.0).is_none());
    }

    #[test]
    fn impossible_travel_none_when_time_not_advanced() {
        let prev = point(Some(BEIJING), 2_000);
        let cur = point(Some(NEW_YORK), 2_000);
        assert!(impossible_travel(&prev, &cur, 900.0).is_none());
        let cur_back = point(Some(NEW_YORK), 1_000);
        assert!(impossible_travel(&prev, &cur_back, 900.0).is_none());
    }
}
```

- [ ] **Step 2: 运行测试**

Run: `cargo test --lib session::geo::`
Expected: 12 个测试全部 PASS

- [ ] **Step 3: 提交**

```bash
git add src/session/geo.rs
git commit -m "feat(session): geo 模块 — haversine、位置比对、不可能旅行"
```

---

### Task 5: `guard.rs` — 骨架、上下文与常数时间比对

**Files:**
- Modify: `src/session/guard.rs`
- Test: `src/session/guard.rs`

- [ ] **Step 1: 写测试与实现**

写入 `src/session/guard.rs`：

```rust
// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use super::SessionConfig;
use super::store::SessionStore;

pub struct SessionGuard<S: SessionStore> {
    /// Task 6 起被读取；在此之前会有 dead_code 警告。
    #[allow(dead_code)]
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
    use super::*;

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
}
```

- [ ] **Step 2: 运行测试**

**前置**：`SessionConfig` 来自 Task 3。

Run: `cargo test --lib session::guard::`
Expected: 6 个测试全部 PASS

- [ ] **Step 3: 恢复被注释的 re-export**

取消 `src/session/mod.rs` 中 `pub use guard::SessionGuard;` 的注释。

- [ ] **Step 4: 提交**

```bash
git add src/session/guard.rs src/session/mod.rs
git commit -m "feat(session): SessionGuard 骨架与常数时间比对 ct_eq"
```

---

### Task 6: `guard.rs` — `bind`

**Files:**
- Modify: `src/session/guard.rs`
- Test: `src/session/guard.rs`

- [ ] **Step 1: 写失败测试**

在 `src/session/guard.rs` 的 `mod tests` 中追加（并更新 `use`）：

```rust
    use super::super::store::{MemoryStore, SessionRecord};
    use super::super::{Decision, SessionError, SessionThreat};
    use crate::Severity;

    const NOW: u64 = 1_000_000;

    fn ctx<'a>(token: &'a str, subject: &'a str, fp: &'a str) -> RequestContext<'a> {
        RequestContext {
            token,
            subject,
            fingerprint: fp,
            location: Some("CN-BJ"),
            coords: Some((39.9042, 116.4074)),
            signature: None,
            at: Some(NOW),
        }
    }

    fn guard() -> SessionGuard<MemoryStore> {
        SessionGuard::new(MemoryStore::new(), SessionConfig::default())
    }

    #[test]
    fn bind_creates_session_record() {
        let g = guard();
        let v = g.bind(&ctx("t1", "u1", "fp1"), NOW).unwrap();
        assert!(v.is_allowed(), "首登无历史，不该报异地: {:?}", v.threats);
        let r = g.store.get("t1").unwrap().expect("record created");
        assert_eq!(r.subject, "u1");
        assert_eq!(r.fingerprint, "fp1");
        assert_eq!(r.issued_at, NOW);
        assert_eq!(r.last_seen, NOW);
        assert_eq!(r.expires_at, NOW + 3600);
        assert!(!r.revoked);
    }

    #[test]
    fn bind_records_login_point() {
        let g = guard();
        g.bind(&ctx("t1", "u1", "fp1"), NOW).unwrap();
        let h = g.store.recent_logins("u1").unwrap();
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].location.as_deref(), Some("CN-BJ"));
        assert_eq!(h[0].at, NOW);
    }

    #[test]
    fn bind_stores_signature_baseline() {
        let g = guard();
        let mut c = ctx("t1", "u1", "fp1");
        c.signature = Some("mac-abc");
        g.bind(&c, NOW).unwrap();
        let r = g.store.get("t1").unwrap().unwrap();
        assert_eq!(r.signature.as_deref(), Some("mac-abc"));
    }

    #[test]
    fn bind_first_login_from_new_region_is_allowed() {
        // 没有任何历史时无法判定异地，必须放行 —— 否则所有新用户首登都被拦
        let g = guard();
        let v = g.bind(&ctx("t1", "u1", "fp1"), NOW).unwrap();
        assert!(v.is_allowed());
        assert!(v.threats.is_empty());
    }

    #[test]
    fn bind_from_different_region_than_history_challenges() {
        let g = guard();
        g.bind(&ctx("t1", "u1", "fp1"), NOW).unwrap();

        let mut c = ctx("t2", "u1", "fp1");
        c.location = Some("US-NY");
        c.coords = None;
        let v = g.bind(&c, NOW + 86_400).unwrap();

        assert_eq!(v.decision, Decision::Challenge);
        assert!(v.threats.contains(&SessionThreat::LocationChanged));
    }

    #[test]
    fn bind_same_region_case_insensitive_is_allowed() {
        let g = guard();
        g.bind(&ctx("t1", "u1", "fp1"), NOW).unwrap();

        let mut c = ctx("t2", "u1", "fp1");
        c.location = Some("cn-bj");
        let v = g.bind(&c, NOW + 86_400).unwrap();
        assert!(v.is_allowed(), "大小写差异不该报异地: {:?}", v.threats);
    }

    #[test]
    fn bind_impossible_travel_blocks() {
        let g = guard();
        g.bind(&ctx("t1", "u1", "fp1"), NOW).unwrap(); // 北京

        let mut c = ctx("t2", "u1", "fp1");
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
    fn bind_rejects_empty_token() {
        let g = guard();
        assert_eq!(
            g.bind(&ctx("", "u1", "fp1"), NOW).unwrap_err(),
            SessionError::EmptyToken
        );
    }

    #[test]
    fn bind_rejects_empty_subject() {
        let g = guard();
        assert_eq!(
            g.bind(&ctx("t1", "", "fp1"), NOW).unwrap_err(),
            SessionError::EmptySubject
        );
    }

    #[test]
    fn bind_rejects_empty_fingerprint() {
        let g = guard();
        assert_eq!(
            g.bind(&ctx("t1", "u1", ""), NOW).unwrap_err(),
            SessionError::EmptyFingerprint
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
        g.bind(&ctx("t1", "u1", "fp1"), NOW).unwrap();
        assert_eq!(g.store.get("t1").unwrap().unwrap().expires_at, NOW + 60);
    }

    #[test]
    fn bind_does_not_compare_against_its_own_login_point() {
        // 同一位置连登两次：第二次的判断依据必须是历史，不是刚写入的本次记录
        let g = guard();
        g.bind(&ctx("t1", "u1", "fp1"), NOW).unwrap();
        let v = g.bind(&ctx("t2", "u1", "fp1"), NOW + 60).unwrap();
        assert!(v.is_allowed(), "同地登录误报: {:?}", v.threats);
    }
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cargo test --lib session::guard::`
Expected: 编译失败 —— `bind` 方法不存在。

- [ ] **Step 3: 实现 `bind`**

在 `src/session/guard.rs` 的 `impl<S: SessionStore> SessionGuard<S>` 块内追加：

```rust
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

        let point = LoginPoint {
            location: ctx.location.map(str::to_string),
            coords: ctx.coords,
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
            coords: ctx.coords,
            signature: ctx.signature.map(str::to_string),
            issued_at: now,
            last_seen: now,
            expires_at: now.saturating_add(self.config.ttl_secs),
            revoked: false,
        })?;
        self.store.record_login(ctx.subject, point)?;

        Ok(SessionVerdict::from_threats(threats))
    }
```

更新文件顶部 `use`：

```rust
use super::geo;
use super::store::{LoginPoint, SessionRecord, SessionStore};
use super::{RequestContext, SessionConfig, SessionError, SessionThreat, SessionVerdict};
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cargo test --lib session::guard::`
Expected: 18 个测试全部 PASS

- [ ] **Step 5: 移除 Task 5 的 `#[allow(dead_code)]`**

`self.store` 与 `self.config` 现已被读取，移除该属性。

- [ ] **Step 6: 提交**

```bash
git add src/session/guard.rs
git commit -m "feat(session): bind —— 建会话、绑指纹、记录位置与异地判定"
```

---

### Task 7: `guard.rs` — `verify` 门槛检查

**Files:**
- Modify: `src/session/guard.rs`
- Test: `src/session/guard.rs`

- [ ] **Step 1: 写失败测试**

在 `mod tests` 中追加：

```rust
    #[test]
    fn verify_unknown_token_blocks() {
        let g = guard();
        let v = g.verify(&ctx("ghost", "u1", "fp1"), NOW);
        assert_eq!(v.decision, Decision::Block);
        assert_eq!(v.threats, vec![SessionThreat::TokenUnknown]);
        assert_eq!(v.severity, Severity::Critical);
    }

    #[test]
    fn verify_empty_token_blocks_as_unknown() {
        // verify 不返回 Result，"客户端没给 token"是正常运行时情况（未登录请求），非编程错误
        let g = guard();
        let v = g.verify(&ctx("", "u1", "fp1"), NOW);
        assert_eq!(v.decision, Decision::Block);
        assert_eq!(v.threats, vec![SessionThreat::TokenUnknown]);
    }

    #[test]
    fn verify_revoked_token_blocks() {
        let g = guard();
        g.bind(&ctx("t1", "u1", "fp1"), NOW).unwrap();
        g.revoke("t1").unwrap();
        let v = g.verify(&ctx("t1", "u1", "fp1"), NOW);
        assert_eq!(v.decision, Decision::Block);
        assert_eq!(v.threats, vec![SessionThreat::TokenRevoked]);
    }

    #[test]
    fn verify_revoked_distinct_from_unknown() {
        // 吊销与"从未存在"必须是不同威胁（用户提示不同：请重新登录 vs 非法请求）
        let g = guard();
        g.bind(&ctx("t1", "u1", "fp1"), NOW).unwrap();
        g.revoke("t1").unwrap();
        let revoked = g.verify(&ctx("t1", "u1", "fp1"), NOW);
        let unknown = g.verify(&ctx("ghost", "u1", "fp1"), NOW);
        assert_ne!(revoked.threats, unknown.threats);
    }

    #[test]
    fn verify_expired_token_blocks_with_low_severity() {
        let g = guard();
        g.bind(&ctx("t1", "u1", "fp1"), NOW).unwrap();
        let v = g.verify(&ctx("t1", "u1", "fp1"), NOW + 3_601);
        assert_eq!(v.decision, Decision::Block);
        assert_eq!(v.threats, vec![SessionThreat::TokenExpired]);
        assert_eq!(v.severity, Severity::Low, "过期是例行情况，非攻击");
    }

    #[test]
    fn verify_expired_distinct_from_unknown() {
        let g = guard();
        g.bind(&ctx("t1", "u1", "fp1"), NOW).unwrap();
        let expired = g.verify(&ctx("t1", "u1", "fp1"), NOW + 3_601);
        let unknown = g.verify(&ctx("ghost", "u1", "fp1"), NOW + 3_601);
        assert_ne!(expired.threats, unknown.threats);
    }

    #[test]
    fn verify_boundary_expires_at_equals_now_is_expired() {
        let g = guard();
        g.bind(&ctx("t1", "u1", "fp1"), NOW).unwrap();
        let v = g.verify(&ctx("t1", "u1", "fp1"), NOW + 3_600);
        assert_eq!(v.threats, vec![SessionThreat::TokenExpired]);
    }

    #[test]
    fn verify_one_second_before_expiry_is_allowed() {
        let g = guard();
        g.bind(&ctx("t1", "u1", "fp1"), NOW).unwrap();
        // ctx() 默认 at = Some(NOW)；这里 now 已是 NOW+3599，不清掉 at 会触发
        // TimestampSkew（偏离 3599 > 300）而干扰本用例关注的过期边界
        let mut c = ctx("t1", "u1", "fp1");
        c.at = None;
        let v = g.verify(&c, NOW + 3_599);
        assert!(v.is_allowed(), "got {:?}", v.threats);
    }
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cargo test --lib session::guard::`
Expected: 编译失败 —— `revoke` 与 `verify` 不存在（`revoke` 在 Task 9 实现，此处先按下方最小实现加入）。

- [ ] **Step 3: 实现 `verify` 门槛部分**

在 `impl` 块内追加：

```rust
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
        if let Ok(history) = self.store.recent_logins(&record.subject) {
            let current = LoginPoint {
                location: ctx.location.map(str::to_string),
                coords: ctx.coords,
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
```

更新文件顶部 `use`：

```rust
use super::geo;
use super::store::{LoginPoint, SessionRecord, SessionStore};
use super::{RequestContext, SessionConfig, SessionError, SessionThreat, SessionVerdict};
use super::StoreError;
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cargo test --lib session::guard::`
Expected: 26 个测试全部 PASS

- [ ] **Step 5: 提交**

```bash
git add src/session/guard.rs
git commit -m "feat(session): verify 门槛检查 —— 未知/吊销/过期 token 与 fail-closed"
```

---

### Task 8: `guard.rs` — `verify` 累积检查与误报防护

**Files:**
- Modify: `src/session/guard.rs`
- Test: `src/session/guard.rs`

- [ ] **Step 1: 写测试**

`verify_binding` 已在 Task 7 实现，本任务补齐边界与误报用例：

```rust
    #[test]
    fn verify_valid_request_is_allowed() {
        let g = guard();
        g.bind(&ctx("t1", "u1", "fp1"), NOW).unwrap();
        let v = g.verify(&ctx("t1", "u1", "fp1"), NOW + 10);
        assert!(v.is_allowed(), "误报: {:?}", v.threats);
        assert!(v.threats.is_empty());
        assert_eq!(v.severity, Severity::Low);
    }

    #[test]
    fn verify_refreshes_last_seen_only_when_allowed() {
        let g = guard();
        g.bind(&ctx("t1", "u1", "fp1"), NOW).unwrap();
        assert!(g.verify(&ctx("t1", "u1", "fp1"), NOW + 10).is_allowed());
        assert_eq!(g.store.get("t1").unwrap().unwrap().last_seen, NOW + 10);
    }

    #[test]
    fn verify_does_not_refresh_last_seen_when_blocked() {
        let g = guard();
        g.bind(&ctx("t1", "u1", "fp1"), NOW).unwrap();
        let mut c = ctx("t1", "u1", "ATTACKER-FP");
        c.at = None;
        let v = g.verify(&c, NOW + 10);
        assert_eq!(v.decision, Decision::Block);
        assert_eq!(
            g.store.get("t1").unwrap().unwrap().last_seen,
            NOW,
            "被拦的请求不该延长会话寿命"
        );
    }

    #[test]
    fn verify_fingerprint_mismatch_is_hijack_block() {
        let g = guard();
        g.bind(&ctx("t1", "u1", "fp1"), NOW).unwrap();
        let mut c = ctx("t1", "u1", "fp2");
        c.at = None;
        let v = g.verify(&c, NOW + 10);
        assert_eq!(v.decision, Decision::Block);
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.threats, vec![SessionThreat::FingerprintMismatch]);
    }

    #[test]
    fn verify_signature_mismatch_is_tamper_block() {
        let g = guard();
        let mut c = ctx("t1", "u1", "fp1");
        c.signature = Some("mac-original");
        g.bind(&c, NOW).unwrap();

        let mut c2 = ctx("t1", "u1", "fp1");
        c2.signature = Some("mac-tampered");
        let v = g.verify(&c2, NOW + 10);
        assert_eq!(v.decision, Decision::Block);
        assert!(v.threats.contains(&SessionThreat::SignatureInvalid));
    }

    #[test]
    fn verify_signature_missing_when_baseline_had_one() {
        let g = guard();
        let mut c = ctx("t1", "u1", "fp1");
        c.signature = Some("mac-original");
        g.bind(&c, NOW).unwrap();

        let v = g.verify(&ctx("t1", "u1", "fp1"), NOW + 10); // 无签名
        assert_eq!(v.decision, Decision::Block);
        assert_eq!(v.threats, vec![SessionThreat::SignatureMissing]);
    }

    #[test]
    fn verify_matching_signature_allows() {
        let g = guard();
        let mut c = ctx("t1", "u1", "fp1");
        c.signature = Some("mac-original");
        g.bind(&c, NOW).unwrap();

        let mut c2 = ctx("t1", "u1", "fp1");
        c2.signature = Some("mac-original");
        assert!(g.verify(&c2, NOW + 10).is_allowed());
    }

    #[test]
    fn verify_no_signature_on_either_side_allows() {
        // 调用方不使用签名时不该被拦
        let g = guard();
        g.bind(&ctx("t1", "u1", "fp1"), NOW).unwrap();
        assert!(g.verify(&ctx("t1", "u1", "fp1"), NOW + 10).is_allowed());
    }

    #[test]
    fn verify_timestamp_skew_challenges() {
        let g = guard();
        g.bind(&ctx("t1", "u1", "fp1"), NOW).unwrap();
        let mut c = ctx("t1", "u1", "fp1");
        c.at = Some(NOW + 3_601); // 偏离 3601 秒 > 300
        let v = g.verify(&c, NOW);
        assert_eq!(v.decision, Decision::Challenge);
        assert!(v.threats.contains(&SessionThreat::TimestampSkew));
    }

    #[test]
    fn verify_timestamp_within_skew_allows() {
        let g = guard();
        g.bind(&ctx("t1", "u1", "fp1"), NOW).unwrap();
        let mut c = ctx("t1", "u1", "fp1");
        c.at = Some(NOW + 10 + 299); // 偏离 299 <= 300
        assert!(g.verify(&c, NOW + 10).is_allowed());
    }

    #[test]
    fn verify_absent_timestamp_skips_skew_check() {
        let g = guard();
        g.bind(&ctx("t1", "u1", "fp1"), NOW).unwrap();
        let mut c = ctx("t1", "u1", "fp1");
        c.at = None;
        assert!(g.verify(&c, NOW + 10).is_allowed());
    }

    #[test]
    fn verify_location_change_challenges() {
        let g = guard();
        g.bind(&ctx("t1", "u1", "fp1"), NOW).unwrap(); // CN-BJ
        let mut c = ctx("t1", "u1", "fp1");
        c.location = Some("US-NY");
        c.coords = None;
        c.at = None;
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
        g.bind(&ctx("t1", "u1", "fp1"), NOW).unwrap(); // 北京
        let mut c = ctx("t1", "u1", "fp1");
        c.location = Some("US-NY");
        c.coords = Some((40.7128, -74.0060));
        c.at = None;
        let v = g.verify(&c, NOW + 3_600); // 1 小时后
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
        let mut c = ctx("t1", "u1", "fp1");
        c.location = None;
        c.coords = None;
        g.bind(&c, NOW).unwrap();

        let mut c2 = ctx("t1", "u1", "fp1");
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
        let mut c = ctx("t1", "u1", "fp1");
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
```

- [ ] **Step 2: 运行测试**

Run: `cargo test --lib session::guard::`
Expected: 42 个测试全部 PASS

**若 `verify_does_not_refresh_last_seen_when_blocked` 失败**：`verify_binding` 里的 `touch` 必须在 `threats.is_empty()` 分支内。

- [ ] **Step 3: clippy 检查**

Run: `cargo clippy --lib -- -D warnings`
Expected: 无警告

- [ ] **Step 4: 提交**

```bash
git add src/session/guard.rs
git commit -m "test(session): verify 累积检查的边界与误报防护用例"
```

---

### Task 9: `guard.rs` — `revoke_all` 与 `rotate`

**Files:**
- Modify: `src/session/guard.rs`
- Test: `src/session/guard.rs`

> `revoke` 已在 Task 7 实现（`verify` 的测试需要它）。本任务补齐另两个。

- [ ] **Step 1: 写失败测试**

在 `mod tests` 中追加：

```rust
    #[test]
    fn revoke_all_kills_every_session_of_subject() {
        let g = guard();
        g.bind(&ctx("t1", "u1", "fp1"), NOW).unwrap();
        g.bind(&ctx("t2", "u1", "fp1"), NOW).unwrap();
        g.bind(&ctx("t3", "u2", "fp2"), NOW).unwrap();

        assert_eq!(g.revoke_all("u1").unwrap(), 2);

        assert_eq!(
            g.verify(&ctx("t1", "u1", "fp1"), NOW + 10).threats,
            vec![SessionThreat::TokenRevoked]
        );
        assert_eq!(
            g.verify(&ctx("t2", "u1", "fp1"), NOW + 10).threats,
            vec![SessionThreat::TokenRevoked]
        );
        // 别的用户不受影响
        assert!(g.verify(&ctx("t3", "u2", "fp2"), NOW + 10).is_allowed());
    }

    #[test]
    fn rotate_issues_new_token_and_kills_old() {
        let g = guard();
        g.bind(&ctx("old", "u1", "fp1"), NOW).unwrap();
        g.rotate("old", "new", &ctx("old", "u1", "fp1"), NOW + 10)
            .unwrap();

        // 旧 token 立即失效
        assert_eq!(
            g.verify(&ctx("old", "u1", "fp1"), NOW + 20).threats,
            vec![SessionThreat::TokenRevoked]
        );
        // 新 token 可用，且继承 subject / 指纹 / 位置基线
        let v = g.verify(&ctx("new", "u1", "fp1"), NOW + 20);
        assert!(v.is_allowed(), "got {:?}", v.threats);
        let r = g.store.get("new").unwrap().unwrap();
        assert_eq!(r.subject, "u1");
        assert_eq!(r.fingerprint, "fp1");
        assert_eq!(r.location.as_deref(), Some("CN-BJ"));
    }

    #[test]
    fn rotate_rejects_unknown_old_token() {
        let g = guard();
        assert_eq!(
            g.rotate("ghost", "new", &ctx("ghost", "u1", "fp1"), NOW).unwrap_err(),
            SessionError::UnknownSession
        );
    }

    #[test]
    fn rotate_rejects_expired_old_token() {
        let g = guard();
        g.bind(&ctx("old", "u1", "fp1"), NOW).unwrap();
        assert_eq!(
            g.rotate("old", "new", &ctx("old", "u1", "fp1"), NOW + 3_601)
                .unwrap_err(),
            SessionError::UnknownSession
        );
    }

    #[test]
    fn rotate_rejects_revoked_old_token() {
        let g = guard();
        g.bind(&ctx("old", "u1", "fp1"), NOW).unwrap();
        g.revoke("old").unwrap();
        assert_eq!(
            g.rotate("old", "new", &ctx("old", "u1", "fp1"), NOW + 10)
                .unwrap_err(),
            SessionError::UnknownSession
        );
    }

    #[test]
    fn rotate_rejects_empty_new_token() {
        let g = guard();
        g.bind(&ctx("old", "u1", "fp1"), NOW).unwrap();
        assert_eq!(
            g.rotate("old", "", &ctx("old", "u1", "fp1"), NOW + 10)
                .unwrap_err(),
            SessionError::EmptyToken
        );
    }

    #[test]
    fn rotate_rejects_fingerprint_mismatch() {
        // 拿别人的 token 换取新 token 必须失败，否则是提权漏洞
        let g = guard();
        g.bind(&ctx("old", "u1", "fp1"), NOW).unwrap();
        assert_eq!(
            g.rotate("old", "new", &ctx("old", "u1", "ATTACKER"), NOW + 10)
                .unwrap_err(),
            SessionError::UnknownSession
        );
    }

    #[test]
    fn rotate_refreshes_ttl() {
        let g = guard();
        g.bind(&ctx("old", "u1", "fp1"), NOW).unwrap();
        g.rotate("old", "new", &ctx("old", "u1", "fp1"), NOW + 1_000)
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
        g.bind(&ctx("old", "u1", "fp1"), NOW).unwrap();
        g.rotate("old", "new", &ctx("old", "VICTIM", "fp1"), NOW + 10)
            .unwrap();
        assert_eq!(g.store.get("new").unwrap().unwrap().subject, "u1");
    }
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cargo test --lib session::guard::`
Expected: 编译失败 —— `revoke_all` / `rotate` 不存在。

- [ ] **Step 3: 实现两个方法**

在 `impl` 块内追加：

```rust
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
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cargo test --lib session::guard::`
Expected: 51 个测试全部 PASS

- [ ] **Step 5: 提交**

```bash
git add src/session/guard.rs
git commit -m "feat(session): revoke_all / rotate 会话生命周期"
```

---

### Task 10: 恢复 re-export 并做集成测试

**Files:**
- Modify: `src/lib.rs`
- Create: `tests/session.rs`

- [ ] **Step 1: 恢复 `lib.rs` 的 re-export**

取消 Task 1 Step 6 注释掉的两段：

```rust
pub use session::{
    Decision, RequestContext, SessionConfig, SessionError, SessionGuard, SessionThreat,
    SessionVerdict, StoreError,
};
pub use session::store::{LoginPoint, MemoryStore, SessionRecord, SessionStore};
```

- [ ] **Step 2: 验证编译**

Run: `cargo build`
Expected: 编译成功，无警告

- [ ] **Step 3: 写集成测试**

现有仓库有 `tests/` 目录，创建 `tests/session.rs`：

```rust
// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use security_rust::session::{
    Decision, MemoryStore, RequestContext, SessionConfig, SessionGuard, SessionThreat, StoreError,
};
use security_rust::session::store::{LoginPoint, SessionRecord, SessionStore};

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

#[test]
fn custom_store_impl_is_pluggable() {
    // 证明多实例部署可以换成 Redis 后端：只需实现 trait
    let g = SessionGuard::new(MemoryStore::new(), SessionConfig::default());
    g.bind(&ctx("t", "u", FP), NOW).unwrap();
    assert!(g.verify(&ctx("t", "u", FP), NOW + 1).is_allowed());
}
```

- [ ] **Step 4: 运行集成测试**

Run: `cargo test --test session`
Expected: 4 个测试全部 PASS

- [ ] **Step 5: 全量验证**

Run: `cargo build --release && cargo test && cargo clippy --all-targets -- -D warnings`
Expected: 全部 PASS，无警告（既有 27 个检测器的测试不受影响）

- [ ] **Step 6: 提交**

```bash
git add src/lib.rs tests/session.rs
git commit -m "test(session): 集成测试 —— fail-closed、端到端生命周期、可插拔存储"
```

---

### Task 11: 文档

**Files:**
- Modify: `README.md`
- Modify: `docs/API.md`

- [ ] **Step 1: README.md 增加会话安全章节**

在 README 的检测器表格之后、赞助章节之前插入：

````markdown
## 会话安全（session）

除字符串检测器外，另提供 `session` 模块覆盖四类**有状态、身份相关**的威胁：

| 能力 | 说明 |
|------|------|
| 客户端被劫持 | token 与登录时绑定的客户端指纹不一致 |
| 篡改数据 | 会话绑定字段被改动，或调用方签名不匹配 |
| 异地登录 | 登录位置偏离历史基线，或出现「不可能旅行」 |
| token 会话 | 会话的建立、校验、过期、吊销、续期 |

`Detector::detect(&str)` 表达不了「token + 指纹 + 位置 + 时间」这种复合输入，因此本模块**不实现 `Detector`**，而是提供独立的 `SessionGuard`。

```rust
use security_rust::session::{Decision, MemoryStore, RequestContext, SessionConfig, SessionGuard};

let guard = SessionGuard::new(MemoryStore::new(), SessionConfig::default());

// 登录：建会话 + 绑指纹 + 记位置
let ctx = RequestContext {
    token: "caller-issued-token",   // token 由调用方签发
    subject: "user-42",
    fingerprint: "ip=1.2.3.4|ua=curl",
    location: Some("CN-BJ"),        // 由调用方用已有 geo 库解析
    coords: Some((39.9042, 116.4074)),
    signature: None,                // 篡改检测的 MAC，由调用方计算
    at: Some(1_700_000_000),
};
guard.bind(&ctx, 1_700_000_000)?;

// 每请求校验
let v = guard.verify(&ctx, 1_700_000_060);
if v.decision == Decision::Block {
    // 拒绝，并记录 v.threats
}
```

### 关键设计取舍

- **零新依赖**：依赖表仍只有 `regex`。代价是 token 与签名由调用方提供，位置由调用方解析。
- **fail-closed**：存储后端故障时返回 `Decision::Block`，绝不放行 —— 后端故障时放行所有请求是一个可被攻击者主动触发的绕过。
- **常数时间比对**：签名与指纹用常数时间比较，避免时序侧信道。
- **可插拔存储**：`SessionStore` trait 抽象，多实例部署实现该 trait 接 Redis 即可，`SessionGuard` 不用改。
````

- [ ] **Step 2: docs/API.md 增加 API 章节**

在 `docs/API.md` 的 `## Scanner` 章节之后追加：

````markdown
## Session 会话安全

### 核心类型

```rust
pub struct RequestContext<'a> {
    pub token: &'a str,
    pub subject: &'a str,
    pub fingerprint: &'a str,
    pub location: Option<&'a str>,
    pub coords: Option<(f64, f64)>,
    pub signature: Option<&'a str>,
    pub at: Option<u64>,
}

pub enum SessionThreat {
    TokenUnknown, TokenExpired, TokenRevoked,
    FingerprintMismatch, SignatureInvalid, SignatureMissing,
    LocationChanged, ImpossibleTravel { kmh: f64 },
    TimestampSkew, StoreUnavailable,
}

pub enum Decision { Allow, Challenge, Block }   // 严格度递增

pub struct SessionVerdict {
    pub decision: Decision,
    pub severity: Severity,
    pub threats: Vec<SessionThreat>,
}
```

### SessionGuard

```rust
impl<S: SessionStore> SessionGuard<S> {
    pub fn new(store: S, config: SessionConfig) -> Self;
    pub fn bind(&self, ctx: &RequestContext, now: u64) -> Result<SessionVerdict, SessionError>;
    pub fn verify(&self, ctx: &RequestContext, now: u64) -> SessionVerdict;
    pub fn revoke(&self, token: &str) -> Result<(), StoreError>;
    pub fn revoke_all(&self, subject: &str) -> Result<usize, StoreError>;
    pub fn rotate(&self, old: &str, new: &str, ctx: &RequestContext, now: u64)
        -> Result<(), SessionError>;
}
```

`verify` 返回 `SessionVerdict` 而非 `Result` —— 认证路径上「拒绝」是正常结果而非错误。

### 威胁判定与处置

| SessionThreat | Severity | Decision |
|---|---|---|
| `TokenUnknown` / `FingerprintMismatch` / `SignatureInvalid` / `ImpossibleTravel` | Critical | Block |
| `TokenRevoked` / `SignatureMissing` / `StoreUnavailable` | High | Block |
| `TokenExpired` | Low | Block |
| `LocationChanged` / `TimestampSkew` | Medium | Challenge |

多个威胁并存时，decision 取最严格者，severity 取最严重者。verdict 为 `Allow` 时 `severity` 是 `Low` 占位值，调用方应只读 `decision`。

### SessionConfig

| 字段 | 默认值 | 说明 |
|---|---|---|
| `ttl_secs` | 3600 | 会话有效期 |
| `impossible_travel_kmh` | 900.0 | 不可能旅行的速度上限（民航巡航上限） |
| `timestamp_skew_secs` | 300 | 请求自称时间的容忍偏离 |

### SessionStore

```rust
pub trait SessionStore: Send + Sync {
    fn put(&self, rec: SessionRecord) -> Result<(), StoreError>;
    fn get(&self, token: &str) -> Result<Option<SessionRecord>, StoreError>;
    fn touch(&self, token: &str, now: u64) -> Result<(), StoreError>;
    fn revoke(&self, token: &str) -> Result<(), StoreError>;
    fn revoke_subject(&self, subject: &str) -> Result<usize, StoreError>;
    fn recent_logins(&self, subject: &str) -> Result<Vec<LoginPoint>, StoreError>;
    fn record_login(&self, subject: &str, point: LoginPoint) -> Result<(), StoreError>;
    fn purge_expired(&self, now: u64) -> Result<usize, StoreError>;
}
```

`MemoryStore` 是自带实现。多实例部署实现该 trait 接 Redis 即可，`SessionGuard` 不用改。

注意：`get` **原样返回记录，不过滤过期** —— 过期判定归 `guard`，否则无法区分 `TokenExpired` 与 `TokenUnknown`。内存回收用 `purge_expired(now)`。
````

- [ ] **Step 3: 核对文档中的签名**

逐项核对：`RequestContext` 的 7 个字段名与顺序、`SessionGuard::new` 的参数顺序、`Decision` / `SessionThreat` 的变体名、`SessionStore` 的 8 个方法签名 —— 必须与 `src/session/` 中的实际定义逐字一致。

- [ ] **Step 4: 提交**

```bash
git add README.md docs/API.md
git commit -m "docs: 会话安全模块 —— README 与 API 参考"
```

---

## 完成标准

```bash
cargo build --release && cargo test && cargo clippy --all-targets -- -D warnings
```

- 既有 27 个检测器测试全绿（未受影响）
- `session` 模块单测 + 集成测试全绿
- 依赖表仍只有 `regex`
- README.md 与 docs/API.md 已更新
