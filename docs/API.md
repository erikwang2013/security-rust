<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust API 参考

[中文](../README.md) | [English](./i18n/en/API.md) | [한국어](./i18n/ko/API.md) | [Русский](./i18n/ru/API.md) | [Deutsch](./i18n/de/API.md) | [Français](./i18n/fr/API.md) | [Español](./i18n/es/API.md) | [Português](./i18n/pt/API.md) | [हिन्दी](./i18n/hi/API.md) | [العربية](./i18n/ar/API.md) | [বাংলা](./i18n/bn/API.md) | [Bahasa Indonesia](./i18n/id/API.md) | [日本語](./i18n/ja/API.md)

---

## 核心 Trait

### `Detector`

所有检测器的唯一契约：

```rust
pub trait Detector {
    fn name(&self) -> &str;
    fn detect(&self, input: &str) -> Option<DetectionResult>;
}
```

- `name()` — 检测器名称（如 `"xss"`、`"sql_injection"`）
- `detect()` — 扫描输入，命中则返回 `Some(DetectionResult)`，未命中返回 `None`

`Detector` 只覆盖 32 个检测器。`session` / `throttle` **不实现**该 trait：它们是**有状态、身份相关**的，要读写的输入是「token + 指纹 + 位置 + 时间」这类复合值，还要访问存储后端，`detect(&str)` 表达不了。它们各自提供显式 API（见下文），也不在 `Scanner` 的装配范围内。

## 检测结果结构

```rust
pub struct DetectionResult {
    pub attack_type: String,      // "xss", "sql_injection" ...
    pub category: AttackCategory, // Injection | Protocol | Data | File
    pub severity: Severity,       // Critical | High | Medium | Low
    pub matched_pattern: String,  // 匹配到的具体模式片段
    pub offset: usize,            // 输入中的字节偏移
    pub message: String,          // 人类可读说明
}
```

## Scanner

### 安装

```toml
[dependencies]
security-rust = "1.1.0"
```

### 快速开始

```rust
use security_rust::Scanner;

fn main() {
    // 零配置：装配全部 32 个检测器
    let scanner = Scanner::default();

    // 扫描输入，返回所有检测到的攻击
    let results = scanner.scan("<script>alert('xss')</script>");

    for r in &results {
        println!("[{}] {} — offset: {}, pattern: {}",
            r.severity, r.message, r.offset, r.matched_pattern);
    }
    // 输出:
    // [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
}
```

### 选择性扫描

```rust
let scanner = Scanner::default();

// 只运行指定的检测器
let results = scanner.scan_with(
    "1 UNION SELECT password FROM users",
    &["sql_injection", "xss"],
);
```

### 自定义配置

```rust
use security_rust::injection::{XssDetector, SqlInjectionDetector};

// 通过 builder 只装配需要的检测器
let scanner = Scanner::builder()
    .with_detector(Box::new(XssDetector))
    .with_detector(Box::new(SqlInjectionDetector))
    .build();
```

### 风险评分

```rust
use security_rust::RiskLevel;

let scanner = Scanner::default();

// 干净输入
let clean = scanner.assess("hello world 123");
assert_eq!(clean.level, RiskLevel::None); // score 0, results 0

// assess 内部就是 scan + score，省得算两遍
let a = scanner.assess("=cmd|' /C calc'!A0 `cat /etc/passwd` ../../../etc/passwd");
println!("{} score={} results={}", a.level, a.score, a.results);
// CRITICAL score=255 results=4
```

### 严重度展示

```rust
use security_rust::Severity;

let r = &results[0];
println!("{}", r.severity);  // CRITICAL | HIGH | MEDIUM | LOW
```

## 模块路径

| 模块 | 路径 | 公开项 | 检测器数 |
|------|------|--------|---------|
| 核心 | `src/lib.rs` `result.rs` `scanner.rs` | `Detector`、`DetectionResult`、`Scanner`、`ScannerBuilder`、`AttackCategory`、`Severity` | — |
| 注入 | `src/injection/` | `*Detector` 共 11 个 | 11 |
| 协议 | `src/protocol/` | `*Detector` 共 11 个 | 11 |
| 数据 | `src/data/` | `*Detector` 共 7 个 | 7 |
| 文件 | `src/file/` | `PathTraversalDetector`、`UploadDetector`、`DataLeakDetector` | 3 |
| 会话 | `src/session/` | `SessionGuard`、`RequestContext`、`SessionVerdict`、`Decision`、`SessionThreat`、`SessionConfig`、`SessionRecord`、`LoginPoint`、`SessionStore`、`MemoryStore`、`SessionError`、`StoreError` | — |
| 限流 | `src/throttle/` | `Throttle`、`ThrottleConfig`、`ThrottleDecision`、`ThrottleStore`、`MemoryThrottleStore` | — |
| 评分 | `src/score.rs` | `RiskLevel`、`RiskAssessment`、`assess`、`score`、`total` | — |

`session` / `throttle` / `score` 的类型都从 crate 根 re-export（如 `use security_rust::{RiskLevel, SessionGuard, Throttle}`），也可走模块路径（如 `use security_rust::session::MemoryStore`）。两个例外：`score` 模块的 `score` / `total` 函数只从模块路径可达（`security_rust::score::score`），crate 根 re-export 的是 `assess`。

## Session 会话安全

会话级威胁检测：客户端劫持（指纹不符）、数据篡改（签名不符）、异地登录 / 不可能旅行、token 过期与吊销。

### 核心类型

| 类型 | 说明 |
|------|------|
| `SessionGuard<S: SessionStore>` | 会话闸门。`bind` / `verify` / `revoke` / `revoke_all` / `rotate` |
| `RequestContext<'a>` | 一次请求的全部输入：`token`、`subject`、`fingerprint`、`location`、`coords`、`signature`、`at` |
| `SessionVerdict` | 校验结论：`decision`、`severity`、`threats` |
| `Decision` | `Allow` < `Challenge` < `Block`（声明顺序即严格度顺序） |
| `SessionThreat` | 11 种威胁，各自映射固定的 `severity()` 与 `decision()` |
| `SessionConfig` | 校准旋钮：`ttl_secs` = 3600、`impossible_travel_kmh` = 900.0、`timestamp_skew_secs` = 300 |
| `SessionStore` | 存储抽象 trait，多实例部署实现它接 Redis 即可 |
| `MemoryStore` | 内置内存后端（`Mutex<HashMap>`，无后台线程） |
| `SessionRecord` / `LoginPoint` | 会话记录 / 登录位置快照 |
| `SessionError` / `StoreError` | 调用方误用 / 存储后端故障 |

### 方法

```rust
impl<S: SessionStore> SessionGuard<S> {
    pub fn new(store: S, config: SessionConfig) -> Self;
    pub fn config(&self) -> &SessionConfig;

    pub fn bind(&self, ctx: &RequestContext, now: u64) -> Result<SessionVerdict, SessionError>;
    pub fn verify(&self, ctx: &RequestContext, now: u64) -> SessionVerdict;
    pub fn revoke(&self, token: &str) -> Result<(), StoreError>;
    pub fn revoke_all(&self, subject: &str) -> Result<usize, StoreError>;
    pub fn rotate(&self, old: &str, new: &str, ctx: &RequestContext, now: u64) -> Result<(), SessionError>;
}
```

| 方法 | 用途 |
|------|------|
| `bind` | 登录：建会话、绑指纹、记登录位置，并返回异地判定 |
| `verify` | 每请求校验，返回处置建议 |
| `revoke` | 吊销单个会话（登出） |
| `revoke_all` | 吊销某 subject 的全部会话（改密码 / 踢下线），返回受影响条数 |
| `rotate` | 续期换 token：旧 token 立即失效，新 token 由调用方提供 |

### 最小示例

```rust
use security_rust::session::{Decision, MemoryStore, RequestContext, SessionConfig, SessionGuard};

let guard = SessionGuard::new(MemoryStore::new(), SessionConfig::default());

let login = RequestContext {
    token: "tok-abc",
    subject: "u-1",
    fingerprint: "ip=1.2.3.4|ua=curl",
    location: Some("CN-BJ"),
    coords: Some((39.9042, 116.4074)),
    signature: None,
    at: None,
};

guard.bind(&login, 1_700_000_000).unwrap();

// 同一个 token，换一个指纹 ⇒ 客户端劫持
let verdict = guard.verify(&RequestContext { fingerprint: "ip=5.6.7.8|ua=curl", ..login }, 1_700_000_010);
assert_eq!(verdict.decision, Decision::Block);
```

### 关键语义

- **`Decision` 三档** — `Allow` 放行；`Challenge` 放行但要求二次验证（异地、时钟偏离、签名意外，这三项是「信号」而非「结论」）；`Block` 拒绝。多个威胁同时命中时取最严格者，`severity` 取最严重者。
- **fail-closed** — 存储后端故障时返回 `SessionThreat::StoreUnavailable` ⇒ `Block`，绝不放行。放行所有请求是一个可被攻击者主动触发的绕过。
- **`verify` 返回 `SessionVerdict` 而非 `Result`** — 认证路径上「拒绝」是正常结果而非错误，强制调用方在类型层面处理每一种拒绝。只有 `bind` / `rotate` 会因调用方误用或后端故障返回 `Result`。
- **只有放行才刷新活跃度** — 被拦的请求不会延长会话寿命。
- **`rotate` 绑定指纹** — 旧会话必须存在、未吊销、未过期，且指纹与本次 `ctx` 相符，否则返回 `UnknownSession`；新记录的身份字段（`subject` / `location` / `coords` / `signature`）一律以服务端记录为准，不接受 `ctx` 覆盖。
- **指纹与签名用常数时间比较** — 直接 `==` 会在首个不同字节处提前返回，泄露「前 N 个字节猜对了」的时序信息。
- **缺失即不判定** — 位置、坐标、时间任一缺失时不产生对应威胁，避免误报；坐标在信任边界清洗，非有限值 / 越界一律视为「没有坐标」。
- **`now` 由调用方传入** — 全部时间参数都是 unix 秒，调用方须保证单调不减。

## Throttle 限流与封禁

滑动窗口计数 + 阈值封禁 + 账户锁定，用于兜住暴力破解与撞库。

### 核心类型

| 类型 | 说明 |
|------|------|
| `Throttle<S: ThrottleStore>` | 限流闸门。`check` / `record_failure` / `record_success` / `reset` / `purge_expired` |
| `ThrottleDecision` | `Allow { remaining }` / `Banned { until }` / `Unavailable` |
| `ThrottleConfig` | `threshold` = 5、`window_secs` = 60、`ban_secs` = 900 |
| `ThrottleStore` | 存储抽象 trait，多实例部署实现它接 Redis 即可 |
| `MemoryThrottleStore` | 内置内存后端 |

### 方法

```rust
impl<S: ThrottleStore> Throttle<S> {
    pub fn new(store: S, config: ThrottleConfig) -> Self;
    pub fn config(&self) -> &ThrottleConfig;

    pub fn check(&self, key: &str, now: u64) -> ThrottleDecision;
    pub fn record_failure(&self, key: &str, now: u64) -> Result<ThrottleDecision, StoreError>;
    pub fn record_success(&self, key: &str) -> Result<(), StoreError>;
    pub fn reset(&self, key: &str) -> Result<(), StoreError>;
    pub fn purge_expired(&self, now: u64) -> Result<usize, StoreError>;
}
```

| 方法 | 用途 |
|------|------|
| `check` | 请求进入时调用：先查封禁，再算剩余额度。**不计入失败** |
| `record_failure` | 认证失败时调用：达到 `threshold` 即封禁并返回 `Banned` |
| `record_success` | 认证成功时调用：**只清失败计数，保留封禁** |
| `reset` | 人工解封 / 解限（清计数 + 清封禁） |
| `purge_expired` | 清除已过期状态，返回清除条数 |

### 最小示例

```rust
use security_rust::throttle::{MemoryThrottleStore, Throttle, ThrottleConfig, ThrottleDecision};

let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());
let key = "acct:u-1"; // key 由调用方构造并规范化
let now = 1_700_000_000;

match throttle.check(key, now) {
    ThrottleDecision::Allow { remaining } => { /* 剩余额度 remaining */ }
    ThrottleDecision::Banned { until } => { /* 封禁中，until 解封 */ }
    ThrottleDecision::Unavailable => { /* 限流后端不可用 */ }
}

let _ = throttle.record_failure(key, now);
```

### 关键语义

- **`Allow { remaining: 0 }` 表示本请求应被拒绝** — 额度已耗尽，不是「还能再试一次」。调用方必须据此拒绝，否则最后一次额度形同虚设。仍叫 `Allow` 是因为此刻并没有封禁在生效——例如 `ban_secs = 0` 的配置下，额度耗尽的 key 会一直落在这一支。
- **`Banned { until }`** — `until` 是解封时刻（unix 秒），`now >= until` 即视为已解封。
- **`Unavailable` 是唯一的 fail-open 例外，且是有意的** — 限流是纵深防御，不是主认证闸门。后端故障时返回 `Banned` 会把全体用户挡在门外（自我 DoS，且攻击者可能主动诱发），而放行只是暂时失去暴力破解防护——主认证闸门 `SessionGuard` 仍然在拦。调用方拿到该变体后自行选择（建议放行 + 告警）。`check` 只把 `Err` 映射到本变体，绝不映射到 `Banned`。
- **key 由调用方构造** — 约定形如 `"ip:1.2.3.4"` 或 `"acct:u-1"`；两类前缀不同，天然互不干扰，可同时启用。不要把用户输入原样当 key：攻击者每次换一个值就能把自己拆成无限多个桶；空 key 同理。调用方须先规范化（截断长度、统一大小写、限制字符集）并保证非空。
- **`record_success` 只清计数、保留封禁** — 「凭据正确 ⇒ 顺手解封」只对 `acct:` 桶成立；对 `ip:` 这类共享桶，换成 `reset` 意味着桶里任意另一个用户认证成功就能替爆破者解封。代价是账户桶下被爆破牵连的用户即使立刻输对密码也要等满 `ban_secs`。
- **`record_failure` 的计数与封禁不原子** — 两次独立的存储写入之间并发一次 `reset` 是可能的，结果是刚认证成功的用户又被封上（可用性问题，不构成绕过）。
- **内存后端的条目数无上限** — `MemoryThrottleStore` 的每个 key 失败列表有界，但 map 条目只增不减。长期运行的进程应按 `window_secs` 量级的间隔定时调用 `purge_expired`。

## Score 风险评分

把单条低危信号聚合成可观测量：多条低危命中叠加可升级，给 WAF 调误报留旋钮。

### 核心类型

| 类型 | 说明 |
|------|------|
| `RiskLevel` | `None` < `Low` < `Medium` < `High` < `Critical`（声明顺序即强度顺序，已派生 `Ord`） |
| `RiskAssessment` | `level` + `score`（原始分）+ `results`（参与聚合的命中条数） |

```rust
pub enum RiskLevel { None, Low, Medium, High, Critical }

pub struct RiskAssessment {
    pub level: RiskLevel,
    pub score: u32,
    pub results: usize,
}

pub fn assess(results: &[DetectionResult]) -> RiskAssessment;
pub fn score(results: &[DetectionResult]) -> RiskLevel;
pub fn total(results: &[DetectionResult]) -> u32;
```

### 评分规则

| `Severity` | 权重 |
|------------|------|
| Critical | 100 |
| High | 40 |
| Medium | 15 |
| Low | 5 |

- 空结果 ⇒ `None`
- 任一 `Severity::Critical` ⇒ 直接 `Critical`（短路，不靠累加）
- 否则按总分分档：`1..=14` → Low、`15..=39` → Medium、`40..=99` → High、`≥100` → Critical
- 因此 3 × Low（15 分）升级为 Medium，8 × Low（40 分）升级为 High

注意 `Severity` 本身**没有** `Ord`（声明顺序是 Critical → Low 递减，派生 `Ord` 会让 `max()` 静默取到最轻的那条），权重表写在评分侧；`RiskLevel` 则相反，声明顺序即强度顺序。

### 最小示例

```rust
use security_rust::{RiskLevel, Scanner};

let scanner = Scanner::default();

// 干净输入
assert_eq!(scanner.assess("hello world 123").level, RiskLevel::None);

// 多条命中叠加：等级、原始分、命中条数一次拿到
let a = scanner.assess("=cmd|' /C calc'!A0 `cat /etc/passwd` ../../../etc/passwd");
println!("{} score={} results={}", a.level, a.score, a.results);
// CRITICAL score=255 results=4

// 已有 scan 结果时直接聚合（assess 从 crate 根导入，
// score / total 走模块路径 security_rust::score::{score, total}）
let results = scanner.scan("<script>alert('xss')</script>");
let a = security_rust::assess(&results);
assert_eq!(a.level, RiskLevel::Critical);
```

## 性能

每个检测器都以静态表 `static PATTERNS: LazyLock<Vec<Regex>>` 持有自己的正则，在进程内首次使用时编译一次，此后每次调用直接复用，不再产生编译开销。全量 32 个检测器的一次扫描在数十微秒量级，成本随检测器数量与输入长度增长；具体数值取决于硬件与负载，建议在自己的机器上实测。适合高吞吐量场景（API 网关、日志管道）。
