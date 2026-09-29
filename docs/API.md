<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust API 参考

[中文](../README.md) | [English](./i18n/en/API.md) | [한국어](./i18n/ko/API.md) | [Русский](./i18n/ru/API.md) | [Deutsch](./i18n/de/API.md) | [Français](./i18n/fr/API.md) | [Español](./i18n/es/API.md) | [Português](./i18n/pt/API.md) | [हिन्दी](./i18n/hi/API.md) | [العربية](./i18n/ar/API.md) | [বাংলা](./i18n/bn/API.md) | [Bahasa Indonesia](./i18n/id/API.md) | [日本語](./i18n/ja/API.md)

---

## 核心 Trait

### `Detector`

所有检测器的唯一契约：

```rust
pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
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

## 两档信号：强信号与弱信号

32 个检测器里有 18 个把模式分成两档（源码里的 `STRONG_PATTERNS` / `WEAK_PATTERNS`）。`DetectionResult` 的字段结构没变，变的是 `severity` 的取值：

| 档位 | 判据 | `severity` | 单条能否越过拒绝线 |
|------|------|-----------|------------------|
| **强信号** | 形态本身只可能来自攻击 | 检测器声明的等级 | 能 |
| **弱信号** | 该 token「出现」而已，正常内容里遍地都是 | 固定 `Severity::Low`（5 分） | **不能** |

同一个检测器、同一个 `attack_type`，只有 `severity` 不同；`detect()` 先试强档，强档不中再试弱档，因此**每个检测器最多返回一条**结果。弱信号仍然被检出，不会静默漏报。

`DetectionResult` 本身不区分档位 —— 想知道一条命中是强是弱，看 `severity == Severity::Low` 即可（弱档是唯一会上报 `Low` 的来源）。参考流水线的拒绝线是 40 分（`risk.level >= RiskLevel::High`，见 [`examples/waf.rs:166`](../examples/waf.rs)），单条弱信号只有 5 分，进不了这一支。

要看穿弱信号背后的攻击，靠的是 `assess()` 把多个检测器的命中叠起来：

```rust
let scanner = Scanner::default();

// 三条弱信号命中三个不同检测器，叠起来才够到 Medium（15 分），仍低于 High
let a = scanner.assess("<script src=\"/app.js\"></script>\n../config\n__proto__");
assert_eq!(a.results, 3);
assert_eq!(a.score, 15);
assert_eq!(a.level, RiskLevel::Medium);
```

被降为弱信号的形态举例（完整名单见各检测器的 `WEAK_PATTERNS`）：`<script src=...>`、单级 `../`、行首 `-2`、裸 `__proto__`、`${env:}`、`X-Forwarded-Host`、`Host: localhost`、裸 `10.0.0.5`、`//evil.com`、`information_schema`。

判据是**形态**不是文件名：同样是 `../`，单级 `../x` 报 `Low`，多级 `../../` 报 `Critical`（[`src/file/path_traversal.rs`](../src/file/path_traversal.rs)）。各检测器能到多高见下方各表与 [README](../README.md) 的功能表。

## Scanner

### 安装

```toml
[dependencies]
security-rust = "2.1.1"
```

### 快速开始

```rust
use security_rust::Scanner;

fn main() {
    // 零配置：装配全部 32 个检测器
    let scanner = Scanner::default();

    // 扫描输入，返回所有检测到的攻击（每个检测器最多一条）
    let results = scanner.scan("<img src=x onerror=alert(1)>");

    for r in &results {
        println!("[{}] {} — offset: {}, pattern: {}",
            r.severity, r.message, r.offset, r.matched_pattern);
    }
    // 输出:
    // [CRITICAL] XSS cross-site scripting detected — offset: 11, pattern: onerror=

    // 弱信号走同一个检测器、同一个 attack_type，只是 severity 为 Low
    let weak = scanner.scan("<script src=\"/app.js\"></script>");
    // [LOW] XSS tag present (weak signal) — offset: 0, pattern: <script>
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
// CRITICAL score=150 results=4
```

### 严重度展示

```rust
use security_rust::Severity;

let r = &results[0];
println!("{}", r.severity);  // CRITICAL | HIGH | MEDIUM | LOW
```

### 状态标签的 `Display`

除 `Severity` / `RiskLevel` 外，下列枚举也实现了 `Display`，日志里可直接插值，不必打印 `Debug` 形状：

| 类型 | 输出 |
|------|------|
| `AttackCategory` | `injection` / `protocol` / `data` / `file` |
| `Decision` | `ALLOW` / `CHALLENGE` / `BLOCK` |
| `SessionThreat` | 人类可读描述（`token expired`、`fingerprint mismatch` …）；`ImpossibleTravel { kmh }` 带上数值：`impossible travel (11205 km/h)` |
| `ThrottleDecision` | `ALLOW` / `BANNED` / `UNAVAILABLE` |
| `ThrottleOutcome` | `ALLOW` / `BANNED` |

```rust
println!("{} {}", verdict.decision, verdict.threats.len());  // BLOCK 2
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
| 限流 | `src/throttle/` | `Throttle`、`ThrottleConfig`、`ThrottleDecision`、`ThrottleOutcome`、`ThrottleStore`、`MemoryThrottleStore` | — |
| 评分 | `src/score.rs` | `RiskLevel`、`RiskAssessment`、`assess`、`score`、`total` | — |
| 宠物 | `src/pet.rs` | `NAME`、`TAGLINE`、`ASCII`、`SVG` | — |

`session` / `throttle` / `score` 的类型都从 crate 根 re-export（如 `use security_rust::{RiskLevel, SessionGuard, Throttle}`），也可走模块路径（如 `use security_rust::session::MemoryStore`）。两个例外：`score` 模块的 `score` / `total` 函数只从模块路径可达（`security_rust::score::score`），crate 根 re-export 的是 `assess`。

## Session 会话安全

会话级威胁检测：客户端劫持（指纹不符）、数据篡改（签名不符）、异地登录 / 不可能旅行、token 过期与吊销。

### 核心类型

| 类型 | 说明 |
|------|------|
| `SessionGuard<S: SessionStore>` | 会话闸门。`bind` / `verify` / `revoke` / `revoke_all` / `rotate` / `purge_expired` |
| `RequestContext<'a>` | 一次请求的全部输入：`token`、`subject`、`fingerprint`、`location`、`coords`、`signature`、`at`。`subject` **仅 `bind` 使用** |
| `SessionVerdict` | 校验结论：`decision`、`severity: Option<Severity>`、`threats` |
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
    pub fn purge_expired(&self, now: u64) -> Result<usize, StoreError>;
}
```

| 方法 | 用途 |
|------|------|
| `bind` | 登录：建会话、绑指纹、记登录位置，并返回异地判定 |
| `verify` | 每请求校验，返回处置建议 |
| `revoke` | 吊销单个会话（登出） |
| `revoke_all` | 吊销某 subject 的全部会话（改密码 / 踢下线），返回受影响条数 |
| `rotate` | 续期换 token：旧 token 立即失效，新 token 由调用方提供 |
| `purge_expired` | 清除过期会话与休眠 subject 的登录历史。**返回值只计会话条数**，不含被回收的登录历史 |

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
- **`severity` 是 `Option<Severity>`，放行为 `None`** — 没有威胁就是没有严重度，由类型说明。不要用某个低危值占位：占位值在日志里跟「发现了一条低危」长得一模一样，一条完全放行的正常请求会被读成有发现。
- **`RequestContext.subject` 仅 `bind` 使用，`verify` 完全忽略它** — 每请求校验的身份一律取自服务端 `SessionRecord`（异地历史按 `record.subject` 聚合），**请求方提供的 subject 不可信**。因此中间件里传 `subject: ""` 是合法的（`bind` 才要求非空）。**绝不要**把请求头里的用户标识填进来当身份：现在它进不了判定，将来重构未必。
- **fail-closed** — 存储后端故障时返回 `SessionThreat::StoreUnavailable` ⇒ `Block`，绝不放行。放行所有请求是一个可被攻击者主动触发的绕过。
- **`verify` 返回 `SessionVerdict` 而非 `Result`** — 认证路径上「拒绝」是正常结果而非错误，强制调用方在类型层面处理每一种拒绝。只有 `bind` / `rotate` 会因调用方误用或后端故障返回 `Result`。
- **只有放行才刷新活跃度** — 被拦的请求不会延长会话寿命。
- **`rotate` 绑定指纹** — 旧会话必须存在、未吊销、未过期，且指纹与本次 `ctx` 相符，否则返回 `UnknownSession`；新记录的身份字段（`subject` / `location` / `coords` / `signature`）一律以服务端记录为准，不接受 `ctx` 覆盖。
- **指纹与签名用常数时间比较** — 直接 `==` 会在首个不同字节处提前返回，泄露「前 N 个字节猜对了」的时序信息。
- **缺失即不判定** — 位置、坐标、时间任一缺失时不产生对应威胁，避免误报；坐标在信任边界清洗，非有限值 / 越界一律视为「没有坐标」。
- **`now` 由调用方传入** — 全部时间参数都是 unix 秒，调用方须保证单调不减。
- **内存后端的 subject 数量无上限** — `MemoryStore` 每个 subject 的登录历史条数由 `MAX_LOGINS_PER_SUBJECT` = 10 限死，**无上限的是 subject 数量**（`Mutex<HashMap>`，无后台线程，条目只增不减）。长期运行的进程应按 `ttl_secs` 量级的间隔定时调用 `purge_expired`：它删除 `expires_at <= now` 的会话，以及最后一个登录点早于 `now - LOGIN_HISTORY_KEEP_SECS`（7 天）的 subject 的整条登录历史。**返回值只计会话条数**，不含被回收的登录历史。回收休眠 subject 的历史，代价是他的下一次登录少做一次异地 / 不可能旅行判定 —— 那是漏报而非误报，之后历史立即重建。

## Throttle 限流与封禁

滑动窗口计数 + 阈值封禁 + 账户锁定，用于兜住暴力破解与撞库。

### 核心类型

| 类型 | 说明 |
|------|------|
| `Throttle<S: ThrottleStore>` | 限流闸门。`check` / `check_any` / `record_failure` / `record_success` / `reset` / `purge_expired` |
| `ThrottleDecision` | `check` / `check_any` 的结果：`Allow { remaining }` / `Banned { until }` / `Unavailable` |
| `ThrottleOutcome` | `record_failure` 的结果：`Allow { remaining }` / `Banned { until }`。**没有 `Unavailable`** —— 存储故障走 `Err` |
| `ThrottleConfig` | `threshold` = 5、`window_secs` = 60、`ban_secs` = 900 |
| `ThrottleStore` | 存储抽象 trait，多实例部署实现它接 Redis 即可 |
| `MemoryThrottleStore` | 内置内存后端 |

### 方法

```rust
impl<S: ThrottleStore> Throttle<S> {
    pub fn new(store: S, config: ThrottleConfig) -> Self;
    pub fn config(&self) -> &ThrottleConfig;

    pub fn check(&self, key: &str, now: u64) -> ThrottleDecision;
    /// 同时检查多个维度（如 [ip_key, account_key]），返回最严格的结果。
    pub fn check_any(&self, keys: &[&str], now: u64) -> ThrottleDecision;
    pub fn record_failure(&self, key: &str, now: u64) -> Result<ThrottleOutcome, StoreError>;
    pub fn record_success(&self, key: &str) -> Result<(), StoreError>;
    pub fn reset(&self, key: &str) -> Result<(), StoreError>;
    pub fn purge_expired(&self, now: u64) -> Result<usize, StoreError>;
}
```

| 方法 | 用途 |
|------|------|
| `check` | 请求进入时调用：先查封禁，再算剩余额度。**不计入失败** |
| `check_any` | 一次查多个维度（如 `[ip_key, account_key]`），返回最严格的结果。**不计入失败** |
| `record_failure` | 认证失败时调用：达到 `threshold` 即封禁并返回 `Banned`；返回 `ThrottleOutcome` 而非 `ThrottleDecision` |
| `record_success` | 认证成功时调用：**只清失败计数，保留封禁** |
| `reset` | 人工解封 / 解限（清计数 + 清封禁） |
| `purge_expired` | 清除已过期状态，返回清除条数 |

### 最小示例

```rust
use security_rust::throttle::{MemoryThrottleStore, Throttle, ThrottleConfig, ThrottleDecision};

let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());
let key = "acct:u-1"; // key 由调用方构造并规范化
let now = 1_700_000_000;

// 真实请求天然有两个维度：IP 与账户。一次问完，合并规则由库负责
match throttle.check_any(&["ip:1.2.3.4", key], now) {
    ThrottleDecision::Allow { remaining } => { /* 剩余额度 remaining */ }
    ThrottleDecision::Banned { until } => { /* 封禁中，until 解封 */ }
    ThrottleDecision::Unavailable => { /* 限流后端不可用 */ }
}

// record_failure 只有两个可达状态：存储故障走 Err，不混在返回值里
match throttle.record_failure(key, now) {
    Ok(outcome) => println!("{outcome}"),
    Err(e) => { /* 后端故障 */ }
}
```

### 关键语义

- **`Allow { remaining: 0 }` 表示本请求应被拒绝** — 额度已耗尽，不是「还能再试一次」。调用方必须据此拒绝，否则最后一次额度形同虚设。仍叫 `Allow` 是因为此刻并没有封禁在生效——例如 `ban_secs = 0` 的配置下，额度耗尽的 key 会一直落在这一支。
- **`Banned { until }`** — `until` 是解封时刻（unix 秒），`now >= until` 即视为已解封。
- **`check_any` 的合并规则** — 任一 `Banned` → `Banned`（取**最晚**的 `until`）；否则任一 `Unavailable` → `Unavailable`；否则 `Allow` 取**最小** `remaining`。每个 key 各自独立查询，**不合并计数**：`ip:` 与 `acct:` 是两类互不干扰的桶，合并会让 NAT 后面的其他人替攻击者吃掉额度。`keys` 为空返回 `Allow { remaining: 0 }` 而非满额 —— 这个数字会写进 `X-RateLimit-*` 响应头，凭空报满额等于谎报额度。
- **`Unavailable` 是唯一的 fail-open 例外，且是有意的** — 限流是纵深防御，不是主认证闸门。后端故障时返回 `Banned` 会把全体用户挡在门外（自我 DoS，且攻击者可能主动诱发），而放行只是暂时失去暴力破解防护——主认证闸门 `SessionGuard` 仍然在拦。调用方拿到该变体后自行选择（建议放行 + 告警）。**该变体只由 `check` / `check_any` 产生**：`check` 只把 `Err` 映射到它，绝不映射到 `Banned`；`record_failure` 返回的 `ThrottleOutcome` 压根没有这个变体（故障走 `Err`），调用方不必为一个永不执行的 `match` 臂写死代码。
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

**这是弱信号唯一的升级路径** —— 单条弱信号 5 分永远越不过 40 分的拒绝线，只有多条（来自不同检测器）叠起来才会。因此把多个维度的输入都喂给同一个 `Scanner`，比只扫单一字段更能看见弱信号背后的攻击；反过来，只扫一个短字段时不必为弱信号做任何处置。

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
// CRITICAL score=150 results=4

// 已有 scan 结果时直接聚合（assess 从 crate 根导入，
// score / total 走模块路径 security_rust::score::{score, total}）
// 用强信号载荷：标签「存在」是弱信号（Low，5 分），单独到不了 Critical。
let results = scanner.scan("<img src=x onerror=alert(1)>");
let a = security_rust::assess(&results);
assert_eq!(a.level, RiskLevel::Critical);
```

## 已知上限

以下几处是**已知且有意保留**的边界，不是待修的缺陷。改动前请先读依据 —— 每一条都出自实测，且都有人试过收紧后撞上同一堵墙。

### `dns_rebinding` 只上报，不拦截

判据是「`Host:` 头里出现内网地址」，而同一个形状也正是 k8s 里每个 pod 间调用（`Host: 10.244.1.5:8080`）、每次本地开发（`Host: localhost:8000`）、每个 Docker 容器网络请求（`172.18.0.2`）。真正的 rebinding 看的是「公网域名 + 解析结果指向内网」，而浏览器发出的 `Host` 恰恰是那个公网域名 —— **单条字符串里看不到解析历史**，本检测器测的形态与攻击形态并不重合，没有可收紧的方向。因此整个检测器只有弱档，一律 `Low`，无论叠加多少条都不会单独越过拒绝线。防护在解析**之后**比对结果 IP，不在字符串层。

### 这个库扫不动自己的源码、测试和文档

签名扫描器的天花板：实测本仓库 298 个文件里有 78 个越过拒绝线，而它们**按构造**全都含有攻击串 —— 测试载荷、检测器源码里的正则字面量自身，以及列出这些模式的 README 与 OWASP 表格。一份 README 不会因为写了 `(a+)+` 而变成缺陷。要扫自己的产物，得先把这些语料排除，或者换一个判据。

### `upload` 一律把 `<%@` / `<?php` 报为 Critical

该检测器的契约是「**这个 blob 是服务端可执行代码**」—— 出现即成立，因此不设强弱分层。JSP 页面与 JSP webshell 的前导字节逐字节相同（`<%@ page language="java" … %>` 与 `<%@ page import="java.io.*" %>` 是同一形态），把 `<%@`/`<%=` 降档等于让 webshell 落到拒绝线以下 —— 那是换个方式删检测。代价是扫描**正在对外提供的**页面（而不是上传的文件）时也会命中，那属于输入域不符。

### `path_traversal` 把 `(?:\.\./){2,}` 报为 Critical

monorepo 里的深层相对路径（`from '../../../shared/domain'`）会命中。没有进一步收紧，因为唯一能把它与攻击分开的约束是目标文件名列表（`../etc/passwd` 那一类），而那只覆盖系统文件 —— 攻方换一个 LFI 目标就绕过去了。

## 性能

每个检测器都以静态表 `static PATTERNS: LazyLock<Vec<Regex>>` 持有自己的正则，在进程内首次使用时编译一次，此后每次调用直接复用，不再产生编译开销。全量 32 个检测器的一次扫描在数十微秒量级，成本随检测器数量与输入长度增长；具体数值取决于硬件与负载，建议在自己的机器上实测。适合高吞吐量场景（API 网关、日志管道）。
