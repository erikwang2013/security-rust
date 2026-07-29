<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# attack-detection

[中文](./README.md) | **English**

A pure Rust attack detection library with 27 detectors across 4 categories. Zero framework dependencies — just `regex` and `thiserror`. Pure string scanning in, structured results out.

---

## Design

### Why Detection, Not Prevention

This library is a **pure input scanner** — receive a string, return structured detection results. It does not bind to any web framework, does not parse HTTP requests/responses, and does not perform real-time blocking. This lets you embed it anywhere: WAF rule engines, log auditing, API gateway pre-validation, CLI security scanners, etc.

### Architecture Principles

- **Single Responsibility** — each detector handles one attack type, holding pre-compiled regex patterns
- **Unified Interface** — the `Detector` trait is the single contract: `fn detect(&self, input: &str) -> Option<DetectionResult>`
- **Default Coverage** — `Scanner::default()` assembles all 27 detectors with zero configuration
- **Optional Configuration** — `Scanner::builder()` lets you selectively add detectors via `.with_detector()`

### Trade-offs

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Regex vs Parser | Regex | Speed-first for detection; regex covers obfuscation/evasion better |
| First-match vs Full-scan | Full-scan | One input may trigger multiple attacks simultaneously |
| Zero-deps vs serde | Zero-deps | Only `regex` + `thiserror` — fast compile, small binary |

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
                       │  │   ├─ ... ×27               │  │
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
  │   10    │  │     9       │  │   5    │  │    3    │
  └─────────┘  └─────────────┘  └────────┘  └─────────┘
```

### Module Structure

| Module | Path | Detectors | Responsibility |
|--------|------|-----------|---------------|
| Core | `src/lib.rs` `result.rs` `scanner.rs` | — | `Detector` trait, `DetectionResult`, `Scanner`/`ScannerBuilder` |
| Injection | `src/injection/` | 10 | XSS, SQLi, CMDi, NoSQL, LDAP, XPATH, JNDI, SSI, GraphQL, SSTI |
| Protocol | `src/protocol/` | 9 | SSRF, XXE, Header Injection, Host Header, Request Smuggling, Open Redirect, CORS, WebSocket, DNS Rebinding |
| Data | `src/data/` | 5 | PHP Deserialization, CSV Injection, Mail Header, JWT Attack, Prototype Pollution |
| File | `src/file/` | 3 | Path Traversal, Malicious Upload, Data Leak |

### Detection Result

```rust
pub struct DetectionResult {
    pub attack_type: String,      // "xss", "sql_injection" ...
    pub category: AttackCategory, // Injection | Protocol | Data | File
    pub severity: Severity,       // Critical | High | Medium | Low
    pub matched_pattern: String,  // Matched pattern fragment
    pub offset: usize,            // Byte offset in input
    pub message: String,          // Human-readable description
}
```

---

## Detectors

### Injection (10 detectors)

| Detector | Patterns | Severity |
|----------|----------|----------|
| **xss** | `<script>`, `onerror=` handlers, `javascript:`, `<svg>`/`<iframe>`, CSS `expression()`, `eval()`, `document.cookie` | Critical |
| **sql_injection** | `UNION SELECT`, `sleep()`/`benchmark()`/`pg_sleep()`, `information_schema`, `exec sp_`/`xp_`, boolean blind `' OR '1'='1`, `LOAD_FILE()`/`INTO OUTFILE` | Critical |
| **command_injection** | Backtick commands, `$()` subshell, pipe chaining, `/dev/tcp` reverse shell, `passthru()`/`shell_exec()`/`system()`, `cmd.exe`/`powershell` | Critical |
| **nosql_injection** | MongoDB `$ne`/`$gt`/`$regex`/`$where`, `$or` injection, auth bypass `{"$gt": ""}` | Critical |
| **ldap_injection** | `(&` `(|` `(!` filters, `*(cn=` enumeration, `objectClass`/`uid` injection | High |
| **xpath_injection** | `' or '1'='1` boolean bypass, `' or true()` function injection, `'] | '` node traversal | High |
| **jndi_injection** | `${jndi:ldap://`, `${lower:j}` obfuscation, `${upper:j}`, `${::-j}` empty-string obfuscation, `${env:}`, `${sys:}` | Critical |
| **ssi_injection** | `<!--#exec cmd=` command exec, `<!--#include file=` file include, `<!--#echo var=` variable output | High |
| **graphql_injection** | `__schema`/`__type` introspection, deeply nested query DoS (≥5 levels) | Medium |
| **ssti** | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<%=` `<%@`, Velocity `#set()`, Python MRO `__mro__`/`__subclasses__()` sandbox escape | Critical |

### Protocol & Request (9 detectors)

| Detector | Patterns | Severity |
|----------|----------|----------|
| **ssrf** | `169.254.169.254` cloud metadata, RFC1918 internal IPs (10.x, 172.16-31.x, 192.168.x), `127.x`, `::1`, `0.0.0.0`, `gopher://`/`dict://`/`ftp://`/`file://` | Critical |
| **xxe** | `<!ENTITY` declaration, `SYSTEM`/`PUBLIC` external references, `%` parameter entity, `<!DOCTYPE` DTD | Critical |
| **header_injection** | `%0d%0a` URL-encoded CRLF, `\r\n` raw CRLF injection | High |
| **host_header** | Multiple Host headers, `X-Forwarded-Host`/`X-Original-URL`/`X-Rewrite-URL` poisoning | High |
| **request_smuggling** | Duplicate `Transfer-Encoding`, `Content-Length: 0` smuggling, `\r\n0\r\n` chunked confusion | High |
| **open_redirect** | `//evil.com` protocol-relative URL, `javascript:`/`data:text/html` pseudo-protocols | Medium |
| **cors** | `Origin: null` bypass, `Access-Control-Allow-Origin: *` + Credentials | Medium |
| **websocket** | `Upgrade: websocket` handshake, `Origin: null` cross-origin WS, `ws://` plaintext | High |
| **dns_rebinding** | Host header with `127.x`/`10.x`/`192.168.x`/`172.16-31.x`, `localhost`, `::1`, `0.0.0.0` | High |

### Data & Serialization (5 detectors)

| Detector | Patterns | Severity |
|----------|----------|----------|
| **deserialization** | PHP `O:digit:`/`C:digit:` serialized objects, `a:digit:{` arrays, `unserialize()`, `__wakeup`/`__destruct`/`__toString` magic methods | Critical |
| **csv_injection** | Leading `=`/`+`/`-`/`@` formula chars, DDE, `cmd|` pipe, `@SUM()` | Medium |
| **mail_header** | `Bcc:`/`Cc:` blind carbon copy, multiple `From:` headers, `MIME-Version:`/`Content-Type: multipart`, `boundary=` manipulation | Medium |
| **jwt_attack** | `alg: none` algorithm bypass, `kid` path traversal, empty signature/payload segment | High |
| **prototype_pollution** | `__proto__`/`constructor.prototype` chain pollution, `__defineGetter__`/`__defineSetter__`/`__lookupGetter__`/`__lookupSetter__` property hijacking | High |

### File & Sensitive Data (3 detectors)

| Detector | Patterns | Severity |
|----------|----------|----------|
| **path_traversal** | `../`/`..\\` directory traversal, `%2e%2e` URL-encoded bypass, `php://filter`/`php://input`/`phar://`/`zip://`/`data://`/`expect://`/`glob://` wrappers, `%00` null byte truncation | Critical |
| **upload** | `<?php`/`<?=` PHP tags, `<%@`/`<%=` ASP tags, `eval($_`/`system($_`/`exec($_`/`passthru($_` backdoor patterns, `$_GET`/`$_POST`/`$_REQUEST`/`$_SERVER` superglobals, `base64_decode()` obfuscation | Critical |
| **data_leak** | 16-digit credit card PAN (Visa/MasterCard/AmEx/Discover/JCB/Diners) with Luhn validation, AWS Access Key `AKIA...`, PEM private key `-----BEGIN`, OpenAI/LLM API Key `sk-...`, DB connection strings `mongodb://`/`mysql://`/`postgresql://`/`redis://`/`jdbc:`, JWT Token | Critical |

---

## Usage

### Quick Start

```rust
use security_rust::Scanner;

fn main() {
    // Zero config: all 27 detectors pre-assembled
    let scanner = Scanner::default();

    // Scan input, get all detected attacks
    let results = scanner.scan("<script>alert('xss')</script>");

    for r in &results {
        println!("[{}] {} — offset: {}, pattern: {}",
            r.severity, r.message, r.offset, r.matched_pattern);
    }
    // Output:
    // [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
}
```

### Selective Scanning

```rust
let scanner = Scanner::default();

// Run only specified detectors
let results = scanner.scan_with(
    "1 UNION SELECT password FROM users",
    &["sql_injection", "xss"],
);
```

### Custom Configuration

```rust
use security_rust::injection::{XssDetector, SqlInjectionDetector};

// Build a scanner with only the detectors you need
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

### Performance

In release builds, single-detector scans run at ~100ns/call (pre-compiled Regex). Full 27-detector scan at ~5μs/call. Suitable for high-throughput scenarios (API gateways, log pipelines).

---

## Development

```bash
# Build
cargo build --release

# Test (46 integration tests)
cargo test

# Lint
cargo clippy -- -D warnings
```

---

## License

MIT — Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
