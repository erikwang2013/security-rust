<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust API Reference

[中文](../../README.md) | [한국어](../ko/API.md) | [Русский](../ru/API.md) | [Deutsch](../de/API.md) | [Français](../fr/API.md) | [Español](../es/API.md) | [Português](../pt/API.md) | [हिन्दी](../hi/API.md) | [العربية](../ar/API.md) | [বাংলা](../bn/API.md) | [Bahasa Indonesia](../id/API.md) | [日本語](../ja/API.md) | [English (本页)](./API.md)

---

## Core Trait

### `Detector`

The single contract for all detectors:

```rust
pub trait Detector {
    fn name(&self) -> &str;
    fn detect(&self, input: &str) -> Option<DetectionResult>;
}
```

- `name()` — detector name (e.g. `"xss"`, `"sql_injection"`)
- `detect()` — scans the input; returns `Some(DetectionResult)` on a match, `None` otherwise

`Detector` is the contract for the 32 string-scanning detectors only. `session` and `throttle` do **not** implement it: they are stateful and identity-aware, and `detect(&str)` cannot carry a composite input such as token + fingerprint + location + time. They take a store parameter instead — see [Session Guard](#session-guard) and [Throttle](#throttle).

## Detection Result Structure

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

### Installation

```toml
[dependencies]
security-rust = "2.0.0"
```

### Quick Start

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

### Selective Scanning

```rust
let scanner = Scanner::default();

// 只运行指定的检测器
let results = scanner.scan_with(
    "1 UNION SELECT password FROM users",
    &["sql_injection", "xss"],
);
```

### Custom Configuration

```rust
use security_rust::injection::{XssDetector, SqlInjectionDetector};

// 通过 builder 只装配需要的检测器
let scanner = Scanner::builder()
    .with_detector(Box::new(XssDetector))
    .with_detector(Box::new(SqlInjectionDetector))
    .build();
```

### Severity Display

```rust
use security_rust::Severity;

let r = &results[0];
println!("{}", r.severity);  // CRITICAL | HIGH | MEDIUM | LOW
```

The other state labels implement `Display` too and print in uppercase: `Decision` (`ALLOW` / `CHALLENGE` / `BLOCK`), `SessionThreat` (e.g. `impossible travel (11205 km/h)`), `AttackCategory` (lowercase, e.g. `injection`), `ThrottleDecision` (`ALLOW` / `BANNED` / `UNAVAILABLE`), and `ThrottleOutcome` (`ALLOW` / `BANNED`).

```rust
println!("{} {}", verdict.decision, verdict.threats.len());  // BLOCK 2
```

### Risk Scoring

```rust
impl Scanner {
    /// Scans, then aggregates the hits into a risk level.
    pub fn assess(&self, input: &str) -> RiskAssessment;
}
```

```rust
use security_rust::{RiskLevel, Scanner};

let scanner = Scanner::default();
let a = scanner.assess("=cmd|' /C calc'!A0 `cat /etc/passwd` ../../../etc/passwd");
// a.level   >= RiskLevel::High   — several medium hits stacked into High
// a.results >= 3                 — number of hits aggregated
// a.score                        — raw weighted points

// A clean input yields RiskLevel::None with score 0.
let clean = scanner.assess("hello world 123");
assert_eq!(clean.level, RiskLevel::None);
```

`RiskLevel` is `None < Low < Medium < High < Critical` (derived `Ord`, ascending, unlike `Severity`) and `Display`s as the uppercase name.

Weights are fixed and live on the scoring side: `Critical` 100, `High` 40, `Medium` 15, `Low` 5. Aggregation rules:

- empty result set → `None`
- any `Severity::Critical` hit → `Critical` (short-circuits; no accumulation needed)
- otherwise the weighted total is banded: `1..=14` → `Low`, `15..=39` → `Medium`, `40..=99` → `High`, `>= 100` → `Critical`

So 3 × Low (15) reaches `Medium` and 8 × Low (40) reaches `High` — stacked low-severity signals escalate rather than being dismissed individually.

The lower-level pieces are also public, under `security_rust::score`: `score(&[DetectionResult]) -> RiskLevel`, `total(&[DetectionResult]) -> u32`, and `assess(&[DetectionResult]) -> RiskAssessment`. `severity_rank` and the weight table stay private.

## Module Paths

| Module | Path | # Detectors |
|------|------|---------|
| Core | `src/lib.rs` `result.rs` `scanner.rs` | — |
| Injection | `src/injection/` | 11 |
| Protocol | `src/protocol/` | 11 |
| Data | `src/data/` | 7 |
| File | `src/file/` | 3 |
| Session | `src/session/` `guard.rs` `store.rs` `geo.rs` | — |
| Throttle | `src/throttle/` `guard.rs` `store.rs` | — |
| Score | `src/score.rs` | — |

`session`, `throttle`, and `score` are re-exported from the crate root alongside the detectors.

## Session Guard

Session security: client hijacking, data tampering, foreign-location login, and token sessions. `SessionGuard` binds a token to a client fingerprint and a location at login, then checks every later request against that baseline.

### Core Types

| Type | Fields / Variants |
|------|------|
| `RequestContext<'a>` | `token: &'a str`, `subject: &'a str`, `fingerprint: &'a str`, `location: Option<&'a str>`, `coords: Option<(f64, f64)>`, `signature: Option<&'a str>`, `at: Option<u64>` |
| `SessionVerdict` | `decision: Decision`, `severity: Option<Severity>` (`None` when allowed), `threats: Vec<SessionThreat>` |
| `Decision` | `Allow` \| `Challenge` \| `Block` |
| `SessionThreat` | `TokenUnknown` \| `TokenExpired` \| `TokenRevoked` \| `FingerprintMismatch` \| `SignatureInvalid` \| `SignatureMissing` \| `SignatureUnexpected` \| `LocationChanged` \| `ImpossibleTravel { kmh: f64 }` \| `TimestampSkew` \| `StoreUnavailable` |
| `SessionConfig` | `ttl_secs: u64`, `impossible_travel_kmh: f64`, `timestamp_skew_secs: u64` |
| `SessionRecord` | Stored session: token, subject, fingerprint, location, coords, signature, `issued_at`, `last_seen`, `expires_at`, `revoked` |
| `LoginPoint` | `location: Option<String>`, `coords: Option<(f64, f64)>`, `at: u64` |
| `SessionError` | `EmptyToken` \| `EmptySubject` \| `EmptyFingerprint` \| `UnknownSession` \| `Store(StoreError)` |
| `StoreError` | `Unavailable` \| `Corrupt` |

`RequestContext` carries no framework types on purpose: tokens, signatures, and coordinates are all supplied by the caller, so the crate still depends on nothing but `regex`. The `subject` is what foreign-location history aggregates on — not the token.

`subject` **is used only by `bind`; `verify` ignores it entirely** — the identity checked on every request always comes from the server-side `SessionRecord` (foreign-location history aggregates on `record.subject`), and the value supplied by the caller is not trusted. `subject: ""` from a middleware is therefore valid (`bind` is the one that requires it non-empty). Which is exactly why a user identifier taken from a request header must **never** be put here: it cannot reach the decision today, but a future refactor is not bound to keep it that way.

### SessionGuard

```rust
impl<S: SessionStore> SessionGuard<S> {
    pub fn new(store: S, config: SessionConfig) -> Self;
    pub fn config(&self) -> &SessionConfig;

    /// Login: create the session, bind the fingerprint, record the location.
    pub fn bind(&self, ctx: &RequestContext, now: u64) -> Result<SessionVerdict, SessionError>;

    /// Per-request verification.
    pub fn verify(&self, ctx: &RequestContext, now: u64) -> SessionVerdict;

    /// Revoke one session (logout).
    pub fn revoke(&self, token: &str) -> Result<(), StoreError>;

    /// Revoke every session for a subject (password change, force logout).
    /// Returns the number of sessions affected.
    pub fn revoke_all(&self, subject: &str) -> Result<usize, StoreError>;

    /// Rotate to a caller-supplied new token, killing the old one.
    pub fn rotate(
        &self,
        old: &str,
        new: &str,
        ctx: &RequestContext,
        now: u64,
    ) -> Result<(), SessionError>;
}
```

```rust
impl SessionVerdict {
    pub fn allow() -> Self;
    pub fn single(threat: SessionThreat) -> Self;
    pub fn from_threats(threats: Vec<SessionThreat>) -> Self;
    pub fn is_allowed(&self) -> bool;
}

impl SessionThreat {
    pub fn severity(&self) -> Severity;
    pub fn decision(&self) -> Decision;
}
```

### Example

```rust
use security_rust::session::{Decision, MemoryStore, RequestContext, SessionConfig, SessionGuard};

let guard = SessionGuard::new(MemoryStore::new(), SessionConfig::default());
let now = 1_700_000_000;

let ctx = RequestContext {
    token: "tok-1",
    subject: "user-42",
    fingerprint: "ip=203.0.113.7|ua=curl",
    location: Some("CN-BJ"),
    coords: Some((39.9042, 116.4074)),
    signature: Some("mac-abc"),
    at: Some(now),
};
let verdict = guard.bind(&ctx, now).unwrap();
assert!(verdict.is_allowed());

// Same token, different client fingerprint → hijacking.
let hijack = RequestContext { fingerprint: "ip=198.51.100.9|ua=curl", ..ctx };
let verdict = guard.verify(&hijack, now + 30);
assert_eq!(verdict.decision, Decision::Block);
```

### Key Semantics

**`verify` returns a verdict, not a `Result`.** On an authentication path, "reject" is a normal outcome rather than an error, and the return type forces callers to handle every rejection. Errors are reserved for caller misuse and store failures, which `verify` converts into a threat.

**Three decision levels.** `Decision` is `Allow < Challenge < Block` (declaration order is `Ord`), and a verdict containing several threats takes the strictest:

| Decision | Threats |
|------|---------|
| `Challenge` | `LocationChanged`, `TimestampSkew`, `SignatureUnexpected` — signals rather than conclusions (travel, clock drift, caller inconsistency), so re-verify instead of rejecting |
| `Block` | Everything else, including `StoreUnavailable` |
| `Allow` | Empty threat list |

`SessionVerdict::from_threats` computes `decision` from `Decision`'s `Ord`, but `severity` via an explicit `severity_rank` — `Severity` deliberately has no `Ord` (its declaration order is Critical → Low, so a derived `max()` would pick the *least* severe). Do not mix the two.

**`allow()` leaves `severity` at `Severity::Low` as a placeholder.** The field is meaningless when there are no threats; read `decision`, not `severity`.

**Fail-closed on store errors.** A store failure yields `SessionThreat::StoreUnavailable` → `Decision::Block`. Failing open would let an attacker trigger a bypass by inducing a backend failure. This covers both a failed `get` and an unreadable login history — skipping the history check silently would disable foreign-location detection entirely.

**`bind` always succeeds for valid input.** A foreign-location verdict does not block the login; it tells the caller whether to run a second factor.

**`rotate` requires a matching fingerprint.** An old token that exists, is unrevoked, and is unexpired is still rejected unless `ctx.fingerprint` matches the stored one — otherwise an attacker holding someone else's token could swap it for one of their own. The new record's identity fields (`subject`, `location`, `coords`, `signature`) come from the server-side record, never from `ctx`.

**Activity is refreshed only on `Allow`.** A blocked request does not extend the session's lifetime.

**Fingerprint and signature comparison is constant-time.** `==` on byte strings returns at the first differing byte, leaking how many leading bytes were guessed correctly. Length mismatch returns `false` immediately — lengths leak, but they are not sensitive.

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

`MemoryStore` is the in-process implementation. There is no background thread: expiry is the guard's business, and reclamation is `purge_expired`. `get` returns records **unfiltered** — if the store dropped expired records, `verify` could not tell `TokenExpired` apart from `TokenUnknown`. Implement this trait over Redis (or similar) for multi-instance deployments.

## Throttle

Sliding-window rate limiting, threshold banning, and account lockout.

### Core Types

| Type | Fields / Variants |
|------|---------|
| `ThrottleConfig` | `threshold: u32`, `window_secs: u64`, `ban_secs: u64` |
| `ThrottleDecision` | `Allow { remaining: u32 }` \| `Banned { until: u64 }` \| `Unavailable` — produced by `check` / `check_any` only |
| `ThrottleOutcome` | `Allow { remaining: u32 }` \| `Banned { until: u64 }` — the result of `record_failure`; it has no `Unavailable`, because a store failure comes back as `Err(StoreError)` |
| `ThrottleStore` | Backing store trait |
| `MemoryThrottleStore` | In-process store |

`ThrottleConfig::default()` is `threshold: 5`, `window_secs: 60`, `ban_secs: 900`. Two boundary values are meaningful rather than degenerate: `threshold: 0` bans on the first failure, and `ban_secs: 0` records without blocking.

### Throttle

```rust
impl<S: ThrottleStore> Throttle<S> {
    pub fn new(store: S, config: ThrottleConfig) -> Self;
    pub fn config(&self) -> &ThrottleConfig;

    /// Call on request entry: checks the ban, then computes the remaining budget.
    pub fn check(&self, key: &str, now: u64) -> ThrottleDecision;

    /// Checks several dimensions at once (e.g. IP + account) and returns the strictest
    /// outcome: any `Banned` wins (latest `until`), else `Unavailable`, else `Allow` with
    /// the smallest `remaining`. An empty slice yields `Allow { remaining: 0 }`.
    pub fn check_any(&self, keys: &[&str], now: u64) -> ThrottleDecision;

    /// Call on authentication failure. Returns `ThrottleOutcome`, not `ThrottleDecision`:
    /// the `Unavailable` variant is unreachable here (a store failure is an `Err`).
    pub fn record_failure(&self, key: &str, now: u64) -> Result<ThrottleOutcome, StoreError>;

    /// Call on authentication success: clears the failure count, keeps any ban.
    pub fn record_success(&self, key: &str) -> Result<(), StoreError>;

    /// Manual unban / unthrottle.
    pub fn reset(&self, key: &str) -> Result<(), StoreError>;

    pub fn purge_expired(&self, now: u64) -> Result<usize, StoreError>;
}
```

### Example

```rust
use security_rust::throttle::{MemoryThrottleStore, Throttle, ThrottleConfig, ThrottleDecision, ThrottleOutcome};

let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());
let now = 1_700_000_000;

assert_eq!(throttle.check("acct:user-42", now), ThrottleDecision::Allow { remaining: 5 });

// Merge several dimensions (e.g. IP + account): the strictest outcome wins.
let _merged = throttle.check_any(&["ip:203.0.113.7", "acct:user-42"], now);

for _ in 0..4 {
    throttle.record_failure("acct:user-42", now).unwrap();
}
// The 5th failure triggers the ban; on a ban_secs = 0 config it would be
// Allow { remaining: 0 } instead.
assert_eq!(
    throttle.record_failure("acct:user-42", now).unwrap(),
    ThrottleOutcome::Banned { until: now + 900 }
);
```

### Key Semantics

**`Allow { remaining: 0 }` means the request should be rejected.** The budget is spent, not "one more attempt left"; a caller that treats it as a pass makes the last unit of budget meaningless. It is not reported as `Banned` because no ban is in effect at that moment — with `ban_secs = 0`, a drained key stays in this arm indefinitely.

**`Unavailable` is a deliberate exception to fail-closed.** Unlike `SessionGuard`, a store failure yields `ThrottleDecision::Unavailable` and **never** `Banned`. Rate limiting is defense in depth, not the primary authentication gate: banning everyone on a backend blip is a self-inflicted DoS that an attacker may even be able to provoke, whereas letting traffic through only loses brute-force protection for that window — `SessionGuard` is still blocking. The caller decides; allowing with an alert is the expected choice. **`Unavailable` is produced by `check` / `check_any` only**: `check` maps only `Err` to it and never to `Banned`, and `ThrottleOutcome` (what `record_failure` returns) has no such variant at all — a store failure there is an `Err`, so the caller never has to write a dead match arm. `check_any` merges several dimensions by strictness: any `Banned` wins with the latest `until`, otherwise any `Unavailable`, otherwise `Allow` with the smallest `remaining`; an empty slice yields `Allow { remaining: 0 }`.

**`record_failure` counts and bans in two separate store operations, so it is not atomic.** A concurrent `reset` between them can re-ban a user who just authenticated — an availability problem, not a bypass, since the failure really was recorded. Eliminating the window means folding count + threshold + ban into a single store operation. Similarly, if the ban write fails this call returns `Err` while the count is already stored; the next `check` then reports `Allow { remaining: 0 }`, and the caller rejects on that.

**Keys are caller-constructed.** `key` is an opaque bucket name; the convention is `format!("ip:{ip}")` for source-based or `format!("acct:{user}")` for account-based throttling. Because the prefixes differ, both can be enabled at once without interference. Do not pass raw user input: an attacker who can vary the value splits into unlimited buckets and the limit disappears, and an empty key puts every failed request into one bucket. Normalize first (truncate, case-fold, restrict the character set) and guarantee non-empty.

**`record_success` clears the failure count but keeps the ban.** "Correct credentials imply not brute-forcing, so unban" only holds for `acct:` buckets. For shared buckets like `ip:`, the ban is shared by everyone behind a NAT or proxy, so clearing it would let *any* other user in the bucket lift a brute-forcer's ban and wipe the count. The trade-off is deliberate: an account caught up in a brute-force campaign waits out the full `ban_secs` (900 by default) even after entering the right password. Bans do not need explicit cleanup — the `now` filter in `is_banned` expires them; use `reset` to lift one early.

### ThrottleStore

```rust
pub trait ThrottleStore: Send + Sync {
    fn record_failure(&self, key: &str, now: u64, window_secs: u64) -> Result<u32, StoreError>;
    fn failure_count(&self, key: &str, now: u64, window_secs: u64) -> Result<u32, StoreError>;
    fn is_banned(&self, key: &str, now: u64) -> Result<Option<u64>, StoreError>;
    fn ban(&self, key: &str, until: u64) -> Result<(), StoreError>;
    fn clear_failures(&self, key: &str) -> Result<(), StoreError>;
    fn reset(&self, key: &str) -> Result<(), StoreError>;
    fn purge_expired(&self, now: u64) -> Result<usize, StoreError>;
}
```

`MemoryThrottleStore` is the in-process implementation. `check` compares `until` against `now` itself rather than trusting the store to filter: a backend that returns the raw value (common in third-party Redis implementations) would otherwise lock a key forever. As with `SessionStore`, implement this trait over Redis for multi-instance deployments.

## Performance

Each detector keeps its patterns in a `static PATTERNS: LazyLock<Vec<Regex>>` table: every regex is compiled once, on first use within the process, and reused on every later call, so no compilation cost remains. A full scan with all 32 detectors takes tens of microseconds per invocation, and the cost grows with the number of detectors and the length of the input. Benchmark on your own hardware and workload for a real figure. Suitable for high-throughput scenarios (API gateways, log pipelines).
