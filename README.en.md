<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust

**🌐 [中文 (原文)](./README.md)**

An attack detection library written in Rust, covering 4 major categories — injection attacks, protocol attacks, data/serialization attacks, and file/sensitive-data leaks — with 32 detectors in total. Alongside them, three stateful guards cover the parts a string scanner cannot reach on its own: session security, rate limiting, and risk scoring. Zero external framework dependencies — the only crate is `regex`.

---

## Design Philosophy

### Why "Detection" Instead of "Blocking"

The 32 detectors are positioned as a **pure input scanner** — each takes a string and returns structured detection results. It is not bound to any web framework, does not parse HTTP requests/responses, and does not implement real-time blocking. This way you can embed it into any pipeline: WAF rule engines, log auditing, API gateway pre-validation, CLI security scanning tools, and more.

The `session`, `throttle`, and `score` modules sit beside the scanner rather than inside it. Session and rate-limiting decisions are **stateful and identity-aware**: a composite input like "token + client fingerprint + location + time" has no single string to hand to `Detector::detect(&str)`. Those modules therefore take an explicit store and are described in their own sections below.

### Architecture Principles

- **Single responsibility** — each detector handles exactly one attack type and internally holds a set of precompiled regex patterns
- **Unified interface** — the `Detector` trait is the single contract for all detectors: `fn detect(&self, input: &str) -> Option<DetectionResult>`
- **Default coverage** — `Scanner::default()` assembles all 32 detectors with one call, usable with zero configuration
- **Optional configuration** — `Scanner::builder()` supports on-demand customization, selectively assembling detectors via `.with_detector()`
- **Stateful guards stay outside the trait** — `session` and `throttle` deliberately do not implement `Detector`; they are parameterized by a store trait instead

### Trade-offs

| Decision | Choice | Rationale |
|------|------|------|
| Regex vs. parser | Regex | Speed first in detection scenarios; regex has better coverage of mutated/bypass patterns |
| First-hit reporting vs. full detection | Full detection | One input can trigger multiple attack types at once; nothing should be missed |
| Zero dependency vs. adding serde | Zero dependency | Depends only on `regex` — fast compilation, small footprint |
| Regex-only scanning vs. stateful reasoning | Both, side by side | String scanning cannot express "same user, different country, 5 minutes later"; `session`/`throttle` add that without pulling the scanner off its contract |

The zero-dependency constraint shapes the stateful modules too: tokens, signatures, and geo coordinates are all **supplied by the caller**, since parsing a JWT or resolving an IP would mean a new dependency. Both take a store trait (`SessionStore` / `ThrottleStore`), so a multi-instance deployment can back them with Redis without touching this crate.

---

## Architecture

```
                       ┌──────────────────────────────────┐
                       │             Scanner              │
                       │  ┌────────────────────────────┐  │
    user input ───────►│  │ scan(input)                │  │      Vec<DetectionResult>
                       │  │ scan_with(input, &[...])   │──┼──►──────────────────────►
                       │  └─────────────┬──────────────┘  │
                       │                │                  │
                       │  ┌─────────────▼──────────────┐  │
                       │  │   Vec<Box<dyn Detector>>   │  │
                       │  │   ├─ XssDetector           │  │
                       │  │   ├─ SqlInjectionDetector  │  │
                       │  │   ├─ ... ×32               │  │
                       │  └────────────────────────────┘  │
                       └──────────────┬───────────────────┘
                                      │
       ┌──────────────────────────────┐
       │       Detector trait         │
       │  fn name(&self) -> &str      │
       │  fn detect(&self, &str)      │
       │       -> Option<Result>      │
       └──────────────┬───────────────┘
                      │
       ┌──────────────┼──────────────┐
       │              │              │
  ┌────┴────┐  ┌──────┴──────┐  ┌───┴────┐  ┌────┴────┐
  │injection│  │  protocol   │  │  data  │  │  file   │
  │  11 个  │  │  11 个      │  │ 7 个   │  │  3 个   │
  └─────────┘  └─────────────┘  └────────┘  └─────────┘
```

The `session`, `throttle`, and `score` modules hold state and are not part of this pipeline — they are documented separately under [Implemented Features](#implemented-features).

### Module Responsibilities

| Module | Path | # Detectors | Responsibility |
|------|------|---------|------|
| Core | `src/lib.rs` `result.rs` `scanner.rs` | — | `Detector` trait, `DetectionResult`, `Scanner`/`ScannerBuilder` |
| Injection | `src/injection/` | 11 | XSS, SQL injection, command injection, NoSQL, LDAP, XPATH, JNDI, SSI, GraphQL, SSTI, format string |
| Protocol | `src/protocol/` | 11 | SSRF, XXE, header injection (CRLF), Host header attacks, request smuggling, open redirect, CORS, WebSocket, DNS rebinding, Log4Shell, HTTP parameter pollution |
| Data | `src/data/` | 7 | PHP deserialization, CSV formula injection, mail header injection, JWT attacks, prototype pollution, spreadsheet formula injection, ReDoS |
| File | `src/file/` | 3 | Path traversal, malicious file upload, sensitive data leaks |
| Session | `src/session/` | — | `SessionGuard`: client hijacking, data tampering, foreign-location login, token sessions |
| Throttle | `src/throttle/` | — | `Throttle`: sliding-window rate limiting, threshold banning, account lockout |
| Score | `src/score.rs` | — | `RiskLevel` / `RiskAssessment`: aggregates low-severity hits into a measurable level |

### Detection Result Structure

`DetectionResult` returns six structured fields: `attack_type`, `category`, `severity`, `matched_pattern`, `offset`, and `message`. See the [API Reference](./docs/API.md) for the full definition.

---

## Implemented Features

### Injection Attacks (11 Detectors)

| Detector | Covered Patterns | Severity |
|--------|---------|--------|
| **xss** | `<script>`, event handlers such as `onerror=`, the `javascript:` pseudo-protocol, `<svg>`/`<iframe>` tags, CSS `expression()`, `eval()`, `document.cookie` | Critical |
| **sql_injection** | `UNION SELECT`, time-based injection via `sleep()`/`benchmark()`/`pg_sleep()`, `information_schema` enumeration, `exec sp_`/`xp_` stored procedures, boolean blind injection patterns like `' OR '1'='1`, `LOAD_FILE()`/`INTO OUTFILE` | Critical |
| **command_injection** | Backtick commands, `$()` subcommands, piped command chaining, `/dev/tcp` reverse shells, PHP functions `passthru()`/`shell_exec()`/`system()`, `cmd.exe`/`powershell` invocations | Critical |
| **nosql_injection** | MongoDB operators `$ne`/`$gt`/`$regex`/`$where`, `$or` injection, authentication bypass via `{"$gt": ""}` | Critical |
| **ldap_injection** | Filter operators `(&` `(\|` `(!`, `*(cn=` attribute enumeration, `objectClass`/`uid` injection | High |
| **xpath_injection** | Boolean bypass `' or '1'='1`, function injection `' or true()`, node traversal `'] \| '` | High |
| **jndi_injection** | `${jndi:ldap://`, `${lower:j}` obfuscation, `${upper:j}` obfuscation, `${::-j}` empty-string obfuscation, `${env:}` environment variable lookups, `${sys:}` system properties | Critical |
| **ssi_injection** | Command execution via `<!--#exec cmd=`, file inclusion via `<!--#include file=`, variable output via `<!--#echo var=`, file info via `<!--#fsize`/`<!--#flastmod` | High |
| **graphql_injection** | `__schema`/`__type` introspection queries, deeply nested DoS (≥5 levels) | Medium |
| **ssti** | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<%=` `<%@`, Velocity `#set()`, Python MRO `__mro__`/`__subclasses__()` sandbox escapes | Critical |
| **format_string** | Memory write via `%n`/`%hn`/`%lln`/`%1$n`, width bombs `%99999999d`, stack reads `%x%x%x`/`%p%p%p`, delimited dumps `%08x.%08x.%08x.%08x`, four or more consecutive `%s`, mixed `%s%x%p%n` chains | Medium |

### Protocol and Request Attacks (11 Detectors)

| Detector | Covered Patterns | Severity |
|--------|---------|--------|
| **ssrf** | `169.254.169.254` cloud metadata, RFC1918 private IPs (10.x, 172.16-31.x, 192.168.x), `127.x` loopback, `::1` IPv6 loopback, `0.0.0.0`, dangerous protocols `gopher://`/`dict://`/`ftp://`/`file://` | Critical |
| **xxe** | `<!ENTITY` entity declarations, `SYSTEM`/`PUBLIC` external references, `%` parameter entities, `<!DOCTYPE` DTD declarations | Critical |
| **header_injection** | Raw `\r\n` CRLF injection before a security-relevant response header (`Set-Cookie`, `Location`, `Content-Length`, `Content-Type`, `Transfer-Encoding`, `Refresh`, `Status`, `WWW-Authenticate`), URL-encoded CRLF `%0d...%0a`, reversed LF-CR order `%0a...%0d` | High |
| **host_header** | Multiple Host header injection, `X-Forwarded-Host`/`X-Original-URL`/`X-Rewrite-URL` poisoning, CRLF smuggling in Host | High |
| **request_smuggling** | Duplicate `Transfer-Encoding` headers, `Content-Length: 0` smuggling, `\r\n0\r\n` chunked termination obfuscation | High |
| **open_redirect** | Protocol-relative URLs `//evil.com`, pseudo-protocol redirects via `javascript:`/`data:text/html` | Medium |
| **cors** | `Origin: null` bypass, `Access-Control-Allow-Origin: *` combined with credentials | Medium |
| **websocket** | `Upgrade: websocket` handshake, cross-origin WS via `Origin: null`, plaintext `ws://` connections | High |
| **dns_rebinding** | Host header as private IP `127.x`/`10.x`/`192.168.x`/`172.16-31.x`, `localhost`, `::1`, `0.0.0.0` | High |
| **log4shell** | `${lower:j}`/`${upper:J}` case-folding, `${::-j}` prefix folding, `${<lookup>:...}ndi:` where the lookup expands into `jndi`, nested `${${<lookup>...}}` expansion, URL-encoded `%24%7b...%7d...ndi` | Critical |
| **hpp** | Mixed `&`/`;` parameter separators (`?a=1&b=2;c=3`) that make two parser layers disagree, repeated keys such as `?id=1&id=2` | Medium |

### Data and Serialization Attacks (7 Detectors)

| Detector | Covered Patterns | Severity |
|--------|---------|--------|
| **deserialization** | PHP serialized objects `O:<digits>:`/`C:<digits>:`, arrays `a:<digits>:{`, `unserialize()` calls, magic methods such as `__wakeup`/`__destruct`/`__toString` | Critical |
| **csv_injection** | Formula characters `=`/`+`/`-`/`@` at the start of a cell, DDE (Dynamic Data Exchange), command pipe `cmd\|`, `@SUM()` functions | Medium |
| **mail_header** | Blind carbon copy injection via `Bcc:`/`Cc:`, multiple senders in `From:`, MIME header injection via `MIME-Version:`/`Content-Type: multipart`, `boundary=` manipulation | Medium |
| **jwt_attack** | `alg: none` algorithm bypass, `kid` path traversal injection, empty signature segment, empty payload segment | High |
| **prototype_pollution** | Prototype chain pollution via `__proto__`/`constructor.prototype`, property hijacking via `__defineGetter__`/`__defineSetter__`/`__lookupGetter__`/`__lookupSetter__` | High |
| **formula_injection** | Command pipe `=cmd\|' /C calc'!A0`, DDE cell references such as `=rundll32\|...!A0`, data-exfiltration functions `HYPERLINK()`/`IMPORTXML()`/`IMPORTDATA()`/`IMPORTRANGE()`/`IMPORTFEED()`/`WEBSERVICE()`/`FILTERXML()`/`RTD()`/`EXEC()`, `DDE(` payloads, legacy `@SUM()`-style formulas | High |
| **redos** | Nested quantifiers `(a+)+`/`(a*)*`/`(\w+\s?)*`, quantifier over bounded repetition `(a+){2,}`, `(a{2,})*`, overlapping alternation `(.\|x)+`/`(\d\|\w)*`, empty branches `(x\|)*` | Medium |

### Files and Sensitive Data (3 Detectors)

| Detector | Covered Patterns | Severity |
|--------|---------|--------|
| **path_traversal** | Directory traversal via `../`/`..\\`, URL-encoded bypass `%2e%2e`, protocol wrappers `php://filter`/`php://input`/`phar://`/`zip://`/`data://`/`expect://`/`glob://`, null-byte truncation `%00` | Critical |
| **upload** | PHP tags `<?php`/`<?=`, ASP tags `<%@`/`<%=`, backdoor patterns `eval($_`/`system($_`/`exec($_`/`passthru($_`, superglobals `$_GET`/`$_POST`/`$_REQUEST`/`$_SERVER`, encoding bypass via `base64_decode()` | Critical |
| **data_leak** | 16-digit credit card PANs (Visa/MasterCard/AmEx/Discover/JCB/Diners), AWS Access Keys `AKIA...`, PEM private key headers `-----BEGIN`, OpenAI/LLM API Keys `sk-...`, database connection strings `mongodb://`/`mysql://`/`postgresql://`/`redis://`/`jdbc:`, JWT tokens | Critical |

---

## Usage

Ready to use with zero configuration:

```rust
use security_rust::Scanner;

let scanner = Scanner::default();
let results = scanner.scan("<script>alert('xss')</script>");
// [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
```

Risk scoring turns the hit list into a single level, so stacked low-severity signals are not silently ignored:

```rust
let assessment = scanner.assess("=cmd|' /C calc'!A0 `cat /etc/passwd` ../../../etc/passwd");
// assessment.level  >= RiskLevel::High
// assessment.results >= 3
// assessment.score  — raw weighted points
```

### Session Security

`SessionGuard` binds a token to a client fingerprint and a location at login, then checks every later request against that baseline:

```rust
use security_rust::session::{Decision, MemoryStore, RequestContext, SessionConfig, SessionGuard};

let guard = SessionGuard::new(MemoryStore::new(), SessionConfig::default());
let now = 1_700_000_000;

// Login: create the session, bind the fingerprint, record the location.
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

// Same token, different client fingerprint → treated as a hijacked session.
let hijack = RequestContext { fingerprint: "ip=198.51.100.9|ua=curl", ..ctx };
let verdict = guard.verify(&hijack, now + 30);
assert_eq!(verdict.decision, Decision::Block);
```

`verify` returns a `SessionVerdict` rather than a `Result`, because on an auth path "reject" is a normal outcome that callers must handle. The verdict carries a `decision` (`Allow` / `Challenge` / `Block`) and the `threats` behind it. Note that `SessionVerdict::allow()` leaves `severity` at its `Severity::Low` placeholder — read `decision`, not `severity`, when there are no threats.

`bind` and `verify` return `Decision::Block` on a store failure rather than allowing the request through: failing open on a backend error is a bypass an attacker can trigger deliberately.

### Rate Limiting and Banning

```rust
use security_rust::throttle::{MemoryThrottleStore, Throttle, ThrottleConfig, ThrottleDecision};

let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());
let now = 1_700_000_000;

// A fresh key has the full budget.
assert_eq!(throttle.check("acct:user-42", now), ThrottleDecision::Allow { remaining: 5 });

// Each failed login consumes one attempt; the 5th returns Banned, not Allow { remaining: 0 }.
for _ in 0..4 {
    throttle.record_failure("acct:user-42", now).unwrap();
}
assert_eq!(
    throttle.record_failure("acct:user-42", now).unwrap(),
    ThrottleDecision::Banned { until: now + 900 }
);
```

`Allow { remaining: 0 }` means the request should be **rejected** — the budget is spent, not "one more try left". It is not reported as `Banned` because no ban is in effect at that moment (with `ban_secs = 0`, a drained key stays in this arm forever).

`Throttle` deliberately does **not** fail closed, unlike `SessionGuard`. A store failure yields `ThrottleDecision::Unavailable`, never `Banned`: rate limiting is defense in depth, and locking every user out on a backend blip would be a self-inflicted DoS, whereas allowing traffic only loses brute-force protection for that window. The caller decides what to do — allowing with an alert is the expected choice.

Keys are caller-constructed (`format!("ip:{ip}")`, `format!("acct:{user}")`) and must be normalized and non-empty: handing raw request values straight to `check` lets an attacker split into unlimited buckets by varying the value, and an empty key puts every failed request in one bucket.

See the [API Reference](./docs/API.md) for the complete API documentation (installation, selective scanning, custom configuration, severity display, store traits, performance).

---

## Development

```bash
# 构建
cargo build --release

# 测试（462 个测试：354 单元 + 46 集成 + 62 会话/限流）
cargo test

# 代码检查
cargo clippy -- -D warnings
```

---

## Donate / Sponsor

If you find this project helpful, donations are welcome (voluntary).

| Alipay | WeChat Pay |
|--------|---------|
| ![Alipay](./docs/alipay.png) | ![WeChat Pay](./docs/weixinpay.png) |

### Global Transfer (International Remittance)

[Beneficiary Information]
- Beneficiary name: WANG KEXUN
- Account number: 881015918251

[Beneficiary Bank]
- ZA Bank SWIFT Code: AABLHKHHXXX
- Bank name: ZA Bank Limited
- Bank code: 387
- Bank address: Core F, Cyberport 3, 100 Cyberport Road, Hong Kong

[Cross-border Remittance Correspondent Bank (if required)]

Please note that the following is the cross-border remittance correspondent bank (intermediary bank) information, not the beneficiary bank information. Please check with your remitting bank whether correspondent bank details are required.

The correspondent bank for remittances in HKD, CNY, and USD is Citibank:
- Bank name: Citibank N.A. Hong Kong
- SWIFT Code: CITIHKHXXXX
- Bank code: 006
- Branch name: Hong Kong Branch
- Branch code: 391
- Bank address: Citibank Tower, Citibank Plaza, 3 Garden Road, Central, Hong Kong

The correspondent bank for other currencies is BNY Mellon:
- Bank name: THE BANK OF NEW YORK MELLON
- SWIFT Code: IRVTUS3NXXX
- Bank address: THE BANK OF NEW YORK MELLON, 240 GREENWICH STREET, NEW YORK, United States

---

## License

MIT — Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
