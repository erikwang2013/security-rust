<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# Session Security — Design Spec

## Overview

在现有 27 个字符串检测器之外，新增 `session` 模块，覆盖四类**有状态、身份相关**的威胁：

| 能力 | 说明 |
|------|------|
| 客户端被劫持 | token 与登录时绑定的客户端指纹（IP/UA 等）不一致 |
| 篡改数据 | 会话绑定字段被改动，或签名不匹配 |
| 异地登录 | 登录位置偏离该身份的历史基线，或出现「不可能旅行」 |
| token 会话 | 会话记录的建立、校验、过期、吊销、续期 |

**与现有模块的根本差异**：`Detector::detect(&str) -> Option<DetectionResult>` 表达不了「token + 指纹 + 位置 + 时间」这种复合输入，且无法持有跨请求状态。因此本模块**不实现 `Detector`**，而是提供独立的 `SessionGuard` API。

**纯增量**：27 个检测器、`Scanner`、`DetectionResult`、`AttackCategory` 均不改动。特别地，**不向 `AttackCategory` 添加 `Session` 变体** —— 该枚举未标记 `#[non_exhaustive]`，新增变体会破坏下游的穷尽 `match`，属于破坏性变更。

唯一触及既有文件的是 `result.rs` 中 `Severity` 增加 `PartialOrd, Ord` 派生（见「威胁判定与处置映射」一节），纯增量 trait impl，非破坏性。

## 设计前提（已确认的决策）

1. **状态归属**：定义 `SessionStore` trait，crate 自带内存实现；多实例部署由调用方实现 trait 接 Redis/DB。
2. **篡改检测**：**签名由调用方计算**，crate 负责常数时间比对与基线持有。不引入密码学依赖。
3. **token 签发**：**token 值由调用方提供**，crate 不铸造 token（零依赖下无法安全地生成随机数）。
4. **位置信号**：调用方传入区域字符串（如 `CN-BJ`）与可选经纬度。零依赖下无法内置 GeoIP 库。

**零新依赖** —— `Cargo.toml` 的 `[dependencies]` 保持只有 `regex`。

## Core Types

```rust
/// 一次请求的全部输入，字段由调用方填写。
pub struct RequestContext<'a> {
    pub token: &'a str,
    pub subject: &'a str,           // 用户标识；异地历史按 subject 聚合，不按 token
    pub fingerprint: &'a str,       // 登录时绑定 → 劫持检测基线
    pub location: Option<&'a str>,  // "CN-BJ"，由调用方用已有 geo 库解析
    pub coords: Option<(f64, f64)>, // (纬度, 经度)，用于「不可能旅行」判定
    pub signature: Option<&'a str>, // 调用方算好的 MAC → 篡改检测
    pub at: Option<u64>,            // 请求自称的时间（如 token 内嵌的 iat）
                                    // 与 now 偏离超窗口 ⇒ TimestampSkew（重放）
}

/// 会话记录 —— 这张表就是「token 会话」。
pub struct SessionRecord {
    pub token: String,
    pub subject: String,
    pub fingerprint: String,
    pub location: Option<String>,
    pub coords: Option<(f64, f64)>,
    pub signature: Option<String>,  // 登录时的签名基线
    pub issued_at: u64,             // unix 秒
    pub last_seen: u64,
    pub expires_at: u64,
    pub revoked: bool,
}

/// 一次登录的位置快照，用于异地检测与不可能旅行。
pub struct LoginPoint {
    pub location: Option<String>,
    pub coords: Option<(f64, f64)>,
    pub at: u64,
}

pub enum SessionThreat {
    TokenUnknown,
    TokenExpired,
    TokenRevoked,
    FingerprintMismatch,                            // 劫持
    SignatureInvalid,                               // 篡改
    SignatureMissing,                               // 篡改（基线有签名，本次没有）
    LocationChanged,                                // 异地
    ImpossibleTravel { kmh: f64 },                  // 异地（铁证）
    TimestampSkew,                                  // 重放
    StoreUnavailable,                               // 后端故障
}

/// 严格度递增（声明顺序即 Ord 顺序），取最严格者作为最终决策。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Decision { Allow, Challenge, Block }

pub struct SessionVerdict {
    pub decision: Decision,
    pub severity: Severity,          // 复用既有 Severity，不新造
    pub threats: Vec<SessionThreat>,
}
```

### 错误类型

```rust
/// 存储后端故障。
pub enum StoreError { Unavailable, Corrupt }

/// 调用方误用。Store 变体用于向上传递后端故障。
pub enum SessionError {
    EmptyToken,
    EmptySubject,
    EmptyFingerprint,
    UnknownSession,   // rotate 的旧 token 不存在、已吊销或已过期
    Store(StoreError),
}
```

错误类型手写 `Display` + `std::error::Error` 实现，**不引入 `thiserror`**。

## Module Structure

```
src/session/
├── mod.rs     公开类型 + re-export
├── store.rs   SessionStore trait / SessionRecord / LoginPoint / MemoryStore
├── guard.rs   SessionGuard：bind / verify / revoke / revoke_all / rotate
└── geo.rs     haversine + 位置比对 + 不可能旅行（纯函数，无状态）
```

`lib.rs` 增加 `pub mod session;` 与相应 re-export。

`geo.rs` 单独拆分：它是纯数学、无状态、可独立测试，并入 `guard.rs` 会使该文件超过 400 行（CLAUDE.md 要求单文件 500 行内）。

## SessionStore

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

### MemoryStore

- `Mutex<HashMap<String, SessionRecord>>` + 每 subject 一条**有界**登录历史（默认保留最近 10 条）。
- **TTL 不做后台线程**（区别于 Go 版 `storage.Memory` 的 `go m.reap()`），且**过期判定归 `guard` 而非 store**：
  - `get()` **原样返回记录，不过滤过期**。原因是 `get` 的签名里没有 `now`，store 无从判断过期；更关键的是，若 `get` 对过期记录返回 `None`，`verify` 就永远无法区分 `TokenExpired` 与 `TokenUnknown`，而这两个威胁在判定表中是独立条目。
  - 过期由 `guard` 用 `now` 判定（流程第 5 步）。
  - 内存回收由 `purge_expired(now) -> usize` 负责，供调用方按需调用。
- `revoke()` 置 `revoked = true` 而不删除记录：这样 `verify` 能区分「已吊销」与「从未存在」。代价是吊销后记录仍占内存，直到自然 TTL 到期。`revoke_subject()` 返回被吊销的会话数。

## 篡改检测的实现

调用方在 `bind` 与 `verify` 时各提供一个签名，crate 做**常数时间比对**：

```rust
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) { diff |= x ^ y; }
    std::hint::black_box(diff) == 0
}
```

crate 的价值在于：**服务端持有「登录时是什么样」的权威基线**，并用常数时间比对 —— 直接用 `==` 比较 MAC 会泄露时序信息。长度差异会泄露，但长度本身不敏感，这是通行做法。

`black_box` 用于阻止优化器将累积循环改写成提前退出。若 `bind` 时存有签名而 `verify` 时未提供 → `SignatureMissing`；若两侧都有但不匹配 → `SignatureInvalid`。

## SessionGuard

```rust
pub struct SessionConfig {
    pub ttl_secs: u64,               // 默认 3600
    pub impossible_travel_kmh: f64,  // 默认 900.0（民航巡航上限）
    pub timestamp_skew_secs: u64,    // 默认 300
}

pub struct SessionGuard<S: SessionStore> { /* store, config */ }

impl<S: SessionStore> SessionGuard<S> {
    pub fn new(store: S, config: SessionConfig) -> Self;

    /// 登录：建会话 + 绑指纹 + 记位置，并返回异地判定。
    pub fn bind(&self, ctx: &RequestContext, now: u64) -> Result<SessionVerdict, SessionError>;

    /// 每请求校验。无返回错误 —— 一切异常都体现在 verdict 中。
    pub fn verify(&self, ctx: &RequestContext, now: u64) -> SessionVerdict;

    pub fn revoke(&self, token: &str) -> Result<(), StoreError>;
    pub fn revoke_all(&self, subject: &str) -> Result<usize, StoreError>;

    /// 续期换 token。新 token 由调用方提供（token 归调用方签发）。
    pub fn rotate(&self, old: &str, new: &str, ctx: &RequestContext, now: u64)
        -> Result<(), SessionError>;
}
```

`rotate` 要求旧 token 存在、未吊销、未过期，**且指纹与本次 `ctx` 相符**（不符返回 `UnknownSession`）。否则等于允许攻击者拿别人的 token 换一个自己的新 token，是提权漏洞。新记录的 `subject` / `location` / `coords` / `signature` 一律以服务端记录为准，不接受 `ctx` 覆盖。

`verify` 返回 `SessionVerdict` 而非 `Result`：认证路径上「拒绝」是正常结果而非错误，强制调用方在类型层面处理每一种拒绝。

`SessionConfig` 只放**校准旋钮**（阈值），威胁→严重度的映射是固定默认值，不做配置。阈值属于与现实对齐的旋钮（各地网络延迟、时钟漂移不同），应由调用方调整。

## 威胁判定与处置映射

| SessionThreat | Severity | Decision |
|---|---|---|
| `TokenUnknown` | Critical | Block |
| `FingerprintMismatch` | Critical | Block |
| `SignatureInvalid` | Critical | Block |
| `ImpossibleTravel` | Critical | Block |
| `TokenRevoked` | High | Block |
| `SignatureMissing` | High | Block |
| `StoreUnavailable` | High | Block |
| `TokenExpired` | Low | Block |
| `LocationChanged` | Medium | Challenge |
| `TimestampSkew` | Medium | Challenge |

- `TokenExpired` 走 Block 但严重度低 —— 它表示必须重新登录，是例行情况而非攻击。
- `LocationChanged` 只 Challenge（可能只是出差），`ImpossibleTravel` 才 Block（物理上不可能）。
- 多个威胁并存时取**最严格**的 decision（`Allow < Challenge < Block`，由 `Decision` 的 `Ord` 派生保证），severity 取**最高**者。
- `Severity` 目前只派生 `PartialEq, Eq`，没有序。为支持「取最高」，在 `result.rs` 给 `Severity` 增加 `PartialOrd, Ord` 派生。这是**唯一改动既有文件的点**，且为纯增量 trait impl，非破坏性变更；`Severity` 的既有行为与全部 27 个检测器不受影响。

## Data Flow

### 登录

```rust
let token = caller_mint();                      // 调用方签发
let v = guard.bind(&ctx, now)?;                 // 建会话 + 记位置 + 异地判定
if v.decision != Decision::Allow {
    step_up_auth(&v);                           // 异地 → 二次验证，但登录仍然成功
}
```

`bind` **也返回 verdict**：异地登录发生在登录时刻，若只在 `verify` 里判定，异地登录将没有地方被上报。

### 每请求

先做门槛检查（记录不存在时后续检查没有基线可比），通过后累积威胁：

```
1. token 为空                          ⇒ TokenUnknown          [门槛]
2. store.get(token) → None             ⇒ TokenUnknown          [门槛]
3. store.get 返回 Err                  ⇒ StoreUnavailable      [门槛]
4. revoked                             ⇒ TokenRevoked          [门槛]
5. expires_at <= now                   ⇒ TokenExpired          [门槛]
   ── 以下需要有效基线，累积而非提前退出 ──
6. fingerprint 常数时间比对             ⇒ FingerprintMismatch      ← 劫持
7. signature 比对                       ⇒ SignatureInvalid/Missing ← 篡改
8. ctx.at 偏离 now 超窗口               ⇒ TimestampSkew
9. 位置比对 + 不可能旅行                ⇒ LocationChanged / ImpossibleTravel
10. 全部通过 → touch() 更新 last_seen   ⇒ Allow
```

累积而非 fail-fast 是为了日志与取证完整。1–5 必须提前退出（记录不存在或不可读时，6–9 没有基线可比）。

注意：`verify` 中 token 为空返回 **verdict**（`TokenUnknown`）而非 `SessionError::EmptyToken` —— `verify` 的签名上没有 `Result`，且「客户端没给 token」是正常的运行时情况（未登录请求），不是调用方编程错误。`EmptyToken` 只出现在 `bind` / `rotate`，那里缺 token 确实是误用。

### 登出与踢下线

```rust
guard.revoke(&token)?;              // 单会话登出
guard.revoke_all(&subject)?;        // 改密码 / 踢掉全部设备
```

## Error Handling

- **fail-closed**：`store` 返回错误时 `verify` 给出 `Decision::Block` + `StoreUnavailable`。安全库**绝不能 fail-open** —— 后端故障时放行所有请求，是一个可被攻击者主动触发的绕过。需要降级的应用可以自行匹配 `StoreUnavailable` 做处置，但默认行为必须是拦住。
- **后端故障在两条路径上形状不同，这是有意的**：
  - `verify`（认证路径）→ 返回 verdict，内含 `StoreUnavailable` + `Decision::Block`，不抛错。
  - `bind` / `rotate`（登录路径）→ 返回 `Err(SessionError::Store(StoreError))`，让调用方知道「会话没能建立」，而不是拿到一个看似成功的 verdict。
- `bind`/`rotate` 的 `SessionError` 还覆盖调用方误用（空 token/subject/fingerprint）—— 那是编程错误，应尽早暴露。
- `verify` 不返回 `Result` —— 认证路径上「拒绝」是正常结果而非错误。

## Dependencies

- `regex` — 既有唯一依赖，本模块不新增
- 不引入 `rand` / `hmac` / `sha2` / `thiserror` / `serde`
- 仅使用 std：`std::sync::Mutex`、`std::collections::HashMap`、`std::time`

## Non-Goals

- **不签发 token** —— token 值由调用方提供
- **不计算签名** —— MAC 由调用方用自己栈内的密码学库计算，crate 只做常数时间比对
- **不内置 GeoIP** —— 区域字符串与经纬度由调用方解析后传入
- **不解析 HTTP** —— 不做请求/响应解析，不绑定 Web 框架
- **不做自动封禁** —— 只给出 verdict，是否封 IP、是否踢下线由调用方决定
- **不实现持久化后端** —— 只提供 `MemoryStore`；Redis/DB 由调用方实现 `SessionStore`
- **不更新 12 个 i18n 文档** —— 本次只更新中文 README 与 `docs/API.md`

## Testing

按仓库既有风格：每个文件内 `#[cfg(test)] mod tests`，`cargo test` 全绿。

| 目标 | 用例 |
|------|------|
| `ct_eq` | 相等 / 差一字节 / 长度不同 / 空串 / 长的相同前缀 |
| `geo` | haversine 已知距离（北京→纽约 ≈ 11000km）、阈值边界、不可能旅行、缺坐标时降级 |
| `store` | put/get/touch/revoke/revoke_all 计数、`get` 原样返回过期记录（不过滤）、`purge_expired`、登录历史有界 |
| `guard` | **每个威胁单独一个用例**、严格度叠加（Block 压过 Challenge）、severity 取最高 |
| 错误处理 | store 故障 → `StoreUnavailable` + Block（fail-closed） |
| 生命周期 | `rotate` 后旧 token 失效、`revoke_all` 后同 subject 全部会话失效 |
| 误报防护 | 正常请求必须 `Allow`（照仓库 `ignores_benign_inputs` 惯例） |

## Verification

```bash
cargo build --release && cargo test && cargo clippy -- -D warnings
```
