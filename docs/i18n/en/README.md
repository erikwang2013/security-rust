<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust

**🌐 [中文 (原文)](../../README.md)**

An attack detection library written in Rust, covering 4 major categories — injection attacks, protocol attacks, data/serialization attacks, and file/sensitive-data leaks — with 27 detectors in total. Zero external framework dependencies, pure string scanning.

---

## Design Philosophy

### Why "Detection" Instead of "Blocking"

This library is positioned as a **pure input scanner** — it takes a string and returns structured detection results. It is not bound to any web framework, does not parse HTTP requests/responses, and does not implement real-time blocking. This way you can embed it into any pipeline: WAF rule engines, log auditing, API gateway pre-validation, CLI security scanning tools, and more.

### Architecture Principles

- **Single responsibility** — each detector handles exactly one attack type and internally holds a set of precompiled regex patterns
- **Unified interface** — the `Detector` trait is the single contract for all detectors: `fn detect(&self, input: &str) -> Option<DetectionResult>`
- **Default coverage** — `Scanner::default()` assembles all 27 detectors with one call, usable with zero configuration
- **Optional configuration** — `Scanner::builder()` supports on-demand customization, selectively assembling detectors via `.with_detector()`

### Trade-offs

| Decision | Choice | Rationale |
|------|------|------|
| Regex vs. parser | Regex | Speed first in detection scenarios; regex has better coverage of mutated/bypass patterns |
| First-hit reporting vs. full detection | Full detection | One input can trigger multiple attack types at once; nothing should be missed |
| Zero dependency vs. adding serde | Zero dependency | Depends only on `regex` + `thiserror` — fast compilation, small footprint |

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
  │  10 个  │  │   9 个      │  │ 5 个   │  │  3 个   │
  └─────────┘  └─────────────┘  └────────┘  └─────────┘
```

### Module Responsibilities

| Module | Path | # Detectors | Responsibility |
|------|------|---------|------|
| Core | `src/lib.rs` `result.rs` `scanner.rs` | — | `Detector` trait, `DetectionResult`, `Scanner`/`ScannerBuilder` |
| Injection | `src/injection/` | 10 | XSS, SQL injection, command injection, NoSQL, LDAP, XPATH, JNDI, SSI, GraphQL, SSTI |
| Protocol | `src/protocol/` | 9 | SSRF, XXE, header injection, Host header attacks, request smuggling, open redirect, CORS, WebSocket, DNS rebinding |
| Data | `src/data/` | 5 | PHP deserialization, CSV formula injection, mail header injection, JWT attacks, prototype pollution |
| File | `src/file/` | 3 | Path traversal, malicious file upload, sensitive data leaks |

### Detection Result Structure

`DetectionResult` returns six structured fields: `attack_type`, `category`, `severity`, `matched_pattern`, `offset`, and `message`. See the [API Reference](./API.md) for the full definition.

---

## Implemented Features

### Injection Attacks (10 Detectors)

| Detector | Covered Patterns | Severity |
|--------|---------|--------|
| **xss** | `<script>`, event handlers such as `onerror=`, the `javascript:` pseudo-protocol, `<svg>`/`<iframe>` tags, CSS `expression()`, `eval()`, `document.cookie` | Critical |
| **sql_injection** | `UNION SELECT`, time-based injection via `sleep()`/`benchmark()`/`pg_sleep()`, `information_schema` enumeration, `exec sp_`/`xp_` stored procedures, boolean blind injection patterns like `' OR '1'='1`, `LOAD_FILE()`/`INTO OUTFILE` | Critical |
| **command_injection** | Backtick commands, `$()` subcommands, piped command chaining, `/dev/tcp` reverse shells, PHP functions `passthru()`/`shell_exec()`/`system()`, `cmd.exe`/`powershell` invocations | Critical |
| **nosql_injection** | MongoDB operators `$ne`/`$gt`/`$regex`/`$where`, `$or` injection, authentication bypass via `{"$gt": ""}` | Critical |
| **ldap_injection** | Filter operators `(&` `(|` `(!`, `*(cn=` attribute enumeration, `objectClass`/`uid` injection | High |
| **xpath_injection** | Boolean bypass `' or '1'='1`, function injection `' or true()`, node traversal `'] | '` | High |
| **jndi_injection** | `${jndi:ldap://`, `${lower:j}` obfuscation, `${upper:j}` obfuscation, `${::-j}` empty-string obfuscation, `${env:}` environment variable lookups, `${sys:}` system properties | Critical |
| **ssi_injection** | Command execution via `<!--#exec cmd=`, file inclusion via `<!--#include file=`, variable output via `<!--#echo var=`, file info via `<!--#fsize`/`<!--#flastmod` | High |
| **graphql_injection** | `__schema`/`__type` introspection queries, deeply nested DoS (≥5 levels) | Medium |
| **ssti** | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<%=` `<%@`, Velocity `#set()`, Python MRO `__mro__`/`__subclasses__()` sandbox escapes | Critical |

### Protocol and Request Attacks (9 Detectors)

| Detector | Covered Patterns | Severity |
|--------|---------|--------|
| **ssrf** | `169.254.169.254` cloud metadata, RFC1918 private IPs (10.x, 172.16-31.x, 192.168.x), `127.x` loopback, `::1` IPv6 loopback, `0.0.0.0`, dangerous protocols `gopher://`/`dict://`/`ftp://`/`file://` | Critical |
| **xxe** | `<!ENTITY` entity declarations, `SYSTEM`/`PUBLIC` external references, `%` parameter entities, `<!DOCTYPE` DTD declarations | Critical |
| **header_injection** | URL-encoded CRLF `%0d%0a`, raw `\r\n` CRLF injection | High |
| **host_header** | Multiple Host header injection, `X-Forwarded-Host`/`X-Original-URL`/`X-Rewrite-URL` poisoning, CRLF smuggling in Host | High |
| **request_smuggling** | Duplicate `Transfer-Encoding` headers, `Content-Length: 0` smuggling, `\r\n0\r\n` chunked termination obfuscation | High |
| **open_redirect** | Protocol-relative URLs `//evil.com`, pseudo-protocol redirects via `javascript:`/`data:text/html` | Medium |
| **cors** | `Origin: null` bypass, `Access-Control-Allow-Origin: *` combined with credentials | Medium |
| **websocket** | `Upgrade: websocket` handshake, cross-origin WS via `Origin: null`, plaintext `ws://` connections | High |
| **dns_rebinding** | Host header as private IP `127.x`/`10.x`/`192.168.x`/`172.16-31.x`, `localhost`, `::1`, `0.0.0.0` | High |

### Data and Serialization Attacks (5 Detectors)

| Detector | Covered Patterns | Severity |
|--------|---------|--------|
| **deserialization** | PHP serialized objects `O:<digits>:`/`C:<digits>:`, arrays `a:<digits>:{`, `unserialize()` calls, magic methods such as `__wakeup`/`__destruct`/`__toString` | Critical |
| **csv_injection** | Formula characters `=`/`+`/`-`/`@` at the start of a cell, DDE (Dynamic Data Exchange), command pipe `cmd|`, `@SUM()` functions | Medium |
| **mail_header** | Blind carbon copy injection via `Bcc:`/`Cc:`, multiple senders in `From:`, MIME header injection via `MIME-Version:`/`Content-Type: multipart`, `boundary=` manipulation | Medium |
| **jwt_attack** | `alg: none` algorithm bypass, `kid` path traversal injection, empty signature segment, empty payload segment | High |
| **prototype_pollution** | Prototype chain pollution via `__proto__`/`constructor.prototype`, property hijacking via `__defineGetter__`/`__defineSetter__`/`__lookupGetter__`/`__lookupSetter__` | High |

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

See the [API Reference](./API.md) for the complete API documentation (installation, selective scanning, custom configuration, severity display, performance).

---

## Development

```bash
# 构建
cargo build --release

# 测试（46 个集成测试）
cargo test

# 代码检查
cargo clippy -- -D warnings
```

---

## Donate / Sponsor

If you find this project helpful, donations are welcome (voluntary).

| Alipay | WeChat Pay |
|--------|---------|
| ![Alipay](./alipay.png) | ![WeChat Pay](./weixinpay.png) |

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
