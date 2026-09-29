<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust

**🌐 [中文 (原文)](../../../README.md)**

An attack detection library written in Rust, covering 4 major categories — injection attacks, protocol attacks, data/serialization attacks, and file/sensitive-data leaks — with 32 detectors in total. Alongside them, three stateful guards cover the parts a string scanner cannot reach on its own: session security, rate limiting, and risk scoring. Zero external framework dependencies — the only crate is `regex`.

The project pet, **Sentri** ([`pet.svg`](../../pet.svg)) — 32 shell plates for 32 detectors. Reports everything, blocks nothing.

---

## Project Pet: Sentri

<img src="../../pet.svg" alt="Sentri — the security-rust project pet" width="340">

A sentry crab holding a magnifying glass and a sign. The character is not decoration — it is this library's design, drawn:

| Feature | What it maps to |
|---------|-----------------|
| 4 rows × 8 shell plates | 32 stateless detectors; the 4 rows are injection / protocol / data / file |
| Magnifying glass in the left claw | **Looking** — `Detector::detect()` only scans; a hit returns one piece of evidence |
| Sign in the right claw (`已上报` — "reported") | **Reporting** — returns `DetectionResult`, never throws, never breaks the call chain |
| Claws that never pinch | The decision belongs to the caller; the one exception is `SessionGuard`, which really does `Block` |
| Monocle | An auditor's habit: every hit carries `matched_pattern` and `offset`, pointing back into the original input |
| `deps: regex ×1` on the nameplate | The zero-dependency promise: `[dependencies]` is only ever `regex` |

Motto: **report everything, block nothing.**

The artwork is bundled into the crate with `include_str!` (no runtime cost — not linked unless used), and the ASCII version goes straight to a terminal or a log:

```rust
println!("{}", security_rust::pet::ASCII);
```

---

## Project Layout

```
security-rust/
├── src/
│   ├── lib.rs              Detector trait (the only contract), regex_detect helper, crate docs
│   ├── scanner.rs          Scanner / ScannerBuilder: assembles all 32 detectors by default
│   ├── result.rs           DetectionResult / AttackCategory / Severity
│   ├── score.rs            Risk scoring: weighted sum + banding → RiskAssessment
│   ├── pet.rs              The project pet (NAME / TAGLINE / ASCII / SVG)
│   ├── injection/          11 injection detectors
│   ├── protocol/           11 protocol detectors
│   ├── data/               7 data detectors
│   ├── file/               3 file detectors
│   ├── session/            SessionGuard + SessionStore (guard / store / geo)
│   └── throttle/           Throttle + ThrottleStore (guard / store)
├── tests/                  7 integration suites: session, throttle, lifecycle, invariants, robustness, end-to-end, multi-key throttle
├── examples/
│   ├── waf.rs              End-to-end pipeline (scan → throttle → session → action)
│   └── axum_middleware.rs  axum middleware integration reference
├── docs/
│   ├── API.md              Full API reference
│   ├── OWASP-COVERAGE.md   Coverage matrix against OWASP attack classes
│   ├── pet.svg             The project pet artwork
│   ├── diagrams/           Architecture / features / lifecycle diagrams (SVG)
│   ├── i18n/               12-language READMEs and API docs
│   └── ...                 Donation QR codes, code-review and test reports
└── Cargo.toml              The single runtime dependency: regex
```

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
| fail-closed vs. fail-open | Authentication fail-closed, throttling fail-open | Letting a session verdict through is a bypass and must be blocked; locking every user out when the throttling backend blips is self-DoS, and the primary gate is still blocking — the disposition belongs to the caller |

The zero-dependency constraint shapes the stateful modules too: tokens, signatures, and geo coordinates are all **supplied by the caller**, since parsing a JWT or resolving an IP would mean a new dependency. Both take a store trait (`SessionStore` / `ThrottleStore`), so a multi-instance deployment can back them with Redis without touching this crate.

### Two Tiers: Strong and Weak Signals

A detector does **not** report every hit at its declared severity. 18 of the 32 detectors split their patterns into two tiers (the `STRONG_PATTERNS` / `WEAK_PATTERNS` statics in the source):

| Tier | Test | Reported severity | Can a single hit cross the reject line? |
|------|------|-------------------|----------------------------------------|
| **Strong** | The shape itself can only come from an attack | The detector's declared level | Yes |
| **Weak** | The token merely *appears* — it is everywhere in ordinary content | Always `Severity::Low` (5 points) | **No** |

Both tiers come from the same detector under the same `attack_type`; only `severity` differs. Weak signals are **still detected** — nothing is silently dropped. They show up in `scan()` and they still accumulate in `assess()`.

The consequence for a caller is direct: **a single weak signal is not grounds for rejection.** The reference pipeline ([`examples/waf.rs:166`](../../../examples/waf.rs)) rejects at `risk.level >= RiskLevel::High` (40 points), and one weak signal is worth 5 — it cannot reach that branch. To see the attack behind weak signals, look at what `assess()` produces once hits from several detectors stack:

```rust
let scanner = Scanner::default();

// Three weak signals from three different detectors — only the stack escalates
let a = scanner.assess("<script src=\"/app.js\"></script>\n../config\n__proto__");
// a.results == 3, a.score == 15 (3 × Low) → RiskLevel::Medium
// still below High; any further hit in the same request crosses the line
```

The patterns demoted to weak are the "appearing is normal" tokens:

| Weak signal | Why it cannot reject on its own |
|-------------|--------------------------------|
| `<script src=...>`, `<iframe>`, `<link>`, `expression(` | Every web page has them |
| A single-level `../` | Relative paths in every source file |
| Line-leading `-2`, `+1` | Markdown list items, negative numbers in prose |
| A bare `__proto__` (prototype read) | Any JS that touches the prototype chain |
| `${env:}` / `${sys:}` | Valid log4j2 configuration syntax |
| `X-Forwarded-Host`, `X-Original-URL` | Reverse proxies add them themselves |
| `Host: 10.244.1.5`, `Host: localhost` | k8s pod-to-pod calls, local development |
| Bare `10.0.0.5`, `192.168.1.1`, `127.0.0.1` | `X-Forwarded-For`, `bind 127.0.0.1` |
| `//evil.com` protocol-relative URL | Source comments, CDN links in docs |
| `information_schema` | PG error logs, SQL tutorials |

That table is only a sample. The test is the **shape**, not the file name: for the same `../`, a single level (`../x`) is weak while multiple levels (`../../`) are strong ([`src/file/path_traversal.rs`](../../../src/file/path_traversal.rs)). The full list lives in each detector's `WEAK_PATTERNS` and in the `weak` markers in the tables below.

---

## Architecture

<img src="../../diagrams/architecture.svg" alt="security-rust architecture: caller → detection layer → scoring layer → guard layer → storage" width="900">

Five layers, top to bottom: **caller** (WAF / gateway / audit / CLI) → **detection layer** (`Scanner` holding `Vec<Box<dyn Detector>>`, 32 detectors in 4 categories) → **scoring layer** (`score::assess`) → **guard layer** (`SessionGuard` / `Throttle`, each bound to a store trait) → **storage abstraction** (built-in `MemoryStore`, Redis implemented by the caller).
*(Diagram annotations are in Chinese; the labels are API names.)*

The `Detector` trait is the detection layer's only contract: `fn detect(&self, input: &str) -> Option<DetectionResult>`. `session`, `throttle`, and `score` do not implement it — their input is not a single string (token + fingerprint + location + time), or they consume scan results instead of raw input — so they answer on their own, as documented below. The red return path on the right marks the library's boundary: **the verdict goes back to the caller to execute**; the library never touches the request itself.

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

`DetectionResult` returns six structured fields: `attack_type`, `category`, `severity`, `matched_pattern`, `offset`, and `message`. See the [API Reference](./API.md) for the full definition.

---

## Implemented Features

<img src="../../diagrams/features.svg" alt="security-rust features: injection 11, protocol 11, data 7, file 3, plus three stateful modules" width="900">

All 32 detectors are assembled by category and enabled by default through `Scanner::default()` with zero configuration. The tables below list what each one covers and its severity. Severity describes a single hit; the aggregated risk is what `Scanner::assess()` returns.

Patterns marked `weak` report `Severity::Low` (5 points) and cannot cross the reject line on their own (see the section above). The Severity column is the detector's **ceiling**: a detector with `weak` entries has both tiers, and its strong patterns still report the declared level. A detector that is weak in full (`dns_rebinding`) has a ceiling of `Low`.
*(Diagram annotations are in Chinese; the labels are API names.)*

### Injection Attacks (11 Detectors)

| Detector | Covered Patterns | Severity |
|--------|---------|--------|
| **xss** | Event handlers such as `onerror=`/`onload=` (the full handler table), the `javascript:`/`vbscript:` pseudo-protocols (scheme followed by a non-blank); `weak`: `<script src=...>`/`<iframe>`/`<embed>`/`<object>`/`<link>` tags, CSS `expression(` | Critical |
| **sql_injection** | `UNION SELECT`, time-based injection via `sleep()`/`benchmark()`/`pg_sleep()` (statement position only), `exec sp_`/`xp_` stored procedures, boolean blind injection patterns like `' OR '1'='1`, `LOAD_FILE()`/`INTO OUTFILE`, `DROP TABLE`/`INSERT INTO`, comment splitting (`UN/**/ION`); `weak`: the word `information_schema` | Critical |
| **command_injection** | `/dev/tcp` reverse shells, `passthru()`/`shell_exec()`/`system("…")`/`popen()`/`pcntl_exec()` call forms, `powershell -Command`/`cmd.exe /c` call forms; `weak`: backtick spans, `$()` subcommands, pipe/`\|\|`/`&&` chaining, `exec(`, `>/dev/null`, `cat /etc/passwd`-style reader+path, bare `cmd.exe`/`powershell` words | Critical |
| **nosql_injection** | MongoDB operators `$ne`/`$gt`/`$regex`/`$where`, `$or` injection, authentication bypass via `{"$gt": ""}` | Critical |
| **ldap_injection** | Filter operators `(&` `(\|` `(!`, `*(cn=` attribute enumeration, `objectClass`/`uid` injection | High |
| **xpath_injection** | Boolean bypass `' or '1'='1`, function injection `' or true()`, node traversal `'] \| '` | High |
| **jndi_injection** | `${jndi:` lookups proper, `${lower:j}`/`${upper:j}` case folding, `${::-j}` empty-string folding (all exist only to obfuscate `jndi`); `weak`: `${env:}`/`${sys:}`/`${java:}` — valid lookup syntax | Critical |
| **ssi_injection** | Command execution via `<!--#exec cmd=`, inclusion via `<!--#include file=` with an absolute path or `..`, environment dump via `<!--#printenv`; `weak`: `<!--#echo var=`, `<!--#fsize`/`<!--#flastmod`, `<!--#config`, routine inclusions like `<!--#include file="header.html"` | High |
| **graphql_injection** | Introspection in query form, `__schema {`/`__type {` (mentioning the field name in prose is not reported); `weak`: `__typename` (Apollo/Relay add it to every query), ≥5 levels of nested braces | Medium |
| **ssti** | Jinja2 `{{ }}` / FreeMarker `${ }` **evaluation inside the delimiters** (`{{7*7}}`, `${7*7}`, `{{config`, `${T(java.lang.Runtime)}`, `${@Type@method}`), template LFI via `{% include '/…'` / `..`, escape chains inside delimiters `__mro__`/`__subclasses__()`/`__globals__`/`__builtins__`/`__class__`/`__dict__`, FreeMarker `?new(`; `weak`: bare template directives `{% %}`/`<%=`/`<%@`/`#set(`, bare magic attributes; the delimiters alone are not a signal, so a plain placeholder like `${x}` is not reported | Critical |
| **format_string** | Memory write via `%n`/`%hn`/`%lln`/`%1$n`, width bombs `%99999999d`, stack reads `%x%x%x`/`%p%p%p`, delimited dumps `%08x.%08x.%08x.%08x`, four or more consecutive `%s`, mixed `%s%x%p%n` chains | Medium |

### Protocol and Request Attacks (11 Detectors)

| Detector | Covered Patterns | Severity |
|--------|---------|--------|
| **ssrf** | `169.254.169.254` cloud metadata and `metadata.google.internal` (no URL context required), private IPs in **URL authority position** (after `//`) `10.x`/`172.16-31.x`/`192.168.x`/`127.x`, `//localhost`, `//0.0.0.0`, `//[::1]`, dangerous protocols `gopher://`/`dict://`/`ftp://user@`/`file:///`; `weak`: the same private literals in **non-URL** positions (`X-Forwarded-For: 10.0.0.5`, `bind 127.0.0.1`, `{"host": "10.0.0.1"}` are byte-identical) | Critical |
| **xxe** | `<!ENTITY` entity declarations, `SYSTEM`/`PUBLIC` external references, `%` parameter entities, `<!DOCTYPE` DTD declarations | Critical |
| **header_injection** | Response-only headers preceded by `\r\n`: `Set-Cookie`/`Location`/`Refresh`/`Status`/`WWW-Authenticate`, or `%0d` together with `%0a` (including reversed `%0a...%0d`). `Content-Length`/`Content-Type`/`Transfer-Encoding` are **request** headers, byte-identical to the header of any well-formed request, so they are no longer signals (the encoded form `%0d%0aContent-Length:` is still covered by `%0d`+`%0a`) | High |
| **host_header** | **Two** `Host:` headers (RFC 7230 §5.4 mandates a 400, two parsers disagree); `weak`: `X-Forwarded-Host`/`X-Original-URL`/`X-Rewrite-URL` — proxies add these themselves, byte-identical to client forgery (`X-Forwarded-For`/`X-Forwarded-Proto` are not reported at all) | High |
| **request_smuggling** | Duplicate `Transfer-Encoding` headers, `Content-Length: 0` smuggling, `\r\n0\r\n` chunked termination obfuscation | High |
| **open_redirect** | Pseudo-protocol redirects via `javascript:`/`data:text/html`/`data:text/plain` (scheme followed by content); `weak`: protocol-relative URLs `//evil.com` — identical to CDN links in source comments and docs | Medium |
| **cors** | `Access-Control-Allow-Origin: null`, and `Access-Control-Allow-Origin: *` **together with** `Access-Control-Allow-Credentials: true`; `weak`: request-side `Origin: null` (sandboxed iframes, `data:` URLs and local files have that origin — it needs an `ACAO: null` echo to hold). Either one alone is normal for public APIs and static assets and is not reported | Medium |
| **websocket** | `Origin: null` co-occurring with a WebSocket upgrade (CSWSH), `ws://` targeting loopback / private / link-local addresses (including the cloud metadata endpoint `169.254.169.254`) | High |
| **dns_rebinding** | Host header as private IP `127.x`/`10.x`/`192.168.x`/`172.16-31.x`, `localhost`, `[::1]`, `0.0.0.0`. **The detector is weak in full**: it always reports `Low` — see Known Limits | Low |
| **log4shell** | `${lower:j}`/`${upper:J}` case-folding, `${::-j}` prefix folding, `${<lookup>:...}ndi:` where the lookup expands into `jndi`, nested `${${<lookup>...}}` expansion, URL-encoded `%24%7b...%7d...ndi` | Critical |
| **hpp** | Mixed `&`/`;` parameter separators (`?a=1&b=2;c=3`) that make two parser layers disagree; `weak`: repeated keys such as `?id=1&id=2` — byte-identical to a legitimate multi-value parameter such as `?tag=rust&tag=web` | Medium |

### Data and Serialization Attacks (7 Detectors)

| Detector | Covered Patterns | Severity |
|--------|---------|--------|
| **deserialization** | PHP serialized objects `O:<digits>:`/`C:<digits>:`, arrays `a:<digits>:{`, `unserialize()` calls, magic methods in **call form** (`__wakeup(`/`__destruct(`/`__construct(`/`__toString(`/`__get(`/`__set(`/`__call(`); `weak`: bare magic-method names (docs discussing them also hit) | Critical |
| **csv_injection** | An `=` directly followed by a non-blank after a `,`/`;`/`\t` separator (a formula in the second cell of a TSV/CSV row), line-leading `DDE`, line-leading `cmd\|`, line-leading `@SUM(`; `weak`: line-leading `=`/`+`/`-` followed by neither a blank nor another delimiter character (`- item` list items, `---` rules, `++i`, `= 5` do not hit). `@` was dropped from the coarse tier entirely (`@media`/`@import` are everywhere in stylesheets); only `@SUM(` remains. Tab and carriage return are **separators**, not formula starts | Medium |
| **mail_header** | Two adjacent `From:` headers, line-leading `MIME-Version:` (a name absent from the HTTP field table); `weak`: line-leading `Cc:`/`Bcc:` — byte-identical to forwarded mail and ingested message bodies. `Content-Type: multipart` and `boundary=` were **deleted** (`Content-Type: multipart/form-data` is the standard header of every file-upload POST). The ceiling is Medium (15 points): it **cannot cross the reject line on its own** | Medium |
| **jwt_attack** | `alg: none` algorithm bypass, `kid` path traversal injection, empty signature segment, empty payload segment | High |
| **prototype_pollution** | `__proto__` as a key or assignment target (`"__proto__":`, `[__proto__]`, `__proto__ = x`), `constructor.prototype`/`constructor[`, `__defineGetter__`/`__defineSetter__`/`__lookupGetter__`/`__lookupSetter__`, `hasOwnProperty[`; `weak`: a bare `__proto__` (`obj.__proto__` is simply how the language reads a prototype) | High |
| **formula_injection** | Command pipe `=cmd\|' /C calc'!A0`, DDE cell references such as `=rundll32\|...!A0`, data-exfiltration functions `HYPERLINK()`/`IMPORTXML()`/`IMPORTDATA()`/`IMPORTRANGE()`/`IMPORTFEED()`/`WEBSERVICE()`/`FILTERXML()`/`RTD()`/`EXEC()`, `DDE(` payloads, legacy `@SUM()`-style formulas | High |
| **redos** | Nested quantifiers `(a+)+`/`(a*)*`/`(\w+\s?)*`, quantifier over bounded repetition `(a+){2,}`, `(a{2,})*`, overlapping alternation `(.\|x)+`/`(\d\|\w)*`, empty branches `(x\|)*` | Medium |

### Files and Sensitive Data (3 Detectors)

| Detector | Covered Patterns | Severity |
|--------|---------|--------|
| **path_traversal** | **Multi-level** traversal `(?:\.\./){2,}`/`(?:\.\.\\){2,}`, URL-encoded bypass `%2e%2e`/`..%2f`/`..%5c`, protocol wrappers `php://filter`/`php://input`/`phar://`/`zip://`/`data://`/`expect://`/`glob://`, null-byte truncation `%00`; `weak`: a single-level `../`/`..\` (identical to a relative path in source or docs) | Critical |
| **upload** | PHP tags `<?php`/`<?=`, ASP tags `<%@`/`<%=`, backdoor patterns `eval($_`/`system($_`/`exec($_`/`passthru($_`, superglobals `$_GET`/`$_POST`/`$_REQUEST`/`$_SERVER`, encoding bypass via `base64_decode()` | Critical |
| **data_leak** | 16-digit credit card PANs (Visa/MasterCard/AmEx/Discover/JCB/Diners), AWS Access Keys `AKIA...`, PEM private key headers `-----BEGIN`, OpenAI/LLM API Keys `sk-...`, database connection strings `mongodb://`/`mysql://`/`postgresql://`/`redis://` (**must carry `@` userinfo**: `mysql://root:secret@db` is reported, `redis://shared-memory` and `postgres://localhost:5432/app` are ordinary config and are **not**), `jdbc:` (no such constraint), JWT tokens | Critical |

---

## Known Limits

The following are **known, deliberately retained** boundaries, not defects awaiting a fix. Each one has measured evidence behind it, and each has already defeated an attempt to tighten it.

### `dns_rebinding` reports, it does not block

Its test is "an internal address appears in `Host:`" — and that same shape is every k8s pod-to-pod call (`Host: 10.244.1.5:8080`), every local development request (`Host: localhost:8000`), and every Docker container-network call (`172.18.0.2`). Real rebinding is "a public domain name + a resolution result pointing inward", and the `Host` the browser sends is precisely that public name — **a single string carries no resolution history**, so the shape this detector tests does not overlap the attack shape. No tightening exists: whatever constraint you add, the test is still "an internal address appears". The detector is therefore weak in full and always reports `Low`; no amount of stacking makes it cross the reject line by itself. Protection belongs after resolution, comparing the resulting IP — not in the string layer.

### This crate cannot scan its own source, tests, or docs

The signature scanner's ceiling: measured over this repository, 78 of 298 files cross the reject line, and every one of them contains attack strings **by construction** — test payloads, the detector sources' own regex literals, and the README/OWASP tables that name the patterns. A README is not defective because it lists `(a+)+`. Scanning your own artifacts means excluding that corpus first, or picking a different test.

### `upload` reports `<%@` / `<?php` as Critical wherever they appear

The detector's contract is "**this blob is server-side executable code**" — the mere presence establishes it, so there is no tier split. A JSP page and a JSP webshell share their preamble byte for byte (`<%@ page language="java" … %>` and `<%@ page import="java.io.*" %>` are the same shape); demoting `<%@`/`<%=` would drop webshell detection below the reject line — that is deletion by another name. The cost is that scanning a page **currently being served** (rather than an uploaded file) also hits; that is an input-domain mismatch — the hit message `Malicious file upload detected` names the domain.

### `path_traversal` reports `(?:\.\./){2,}` as Critical

A deep relative path in a monorepo (`from '../../../shared/domain'`) matches. It is not tightened further because the only constraint that separates it from an attack is a target-name list (`../etc/passwd` and friends), which covers system files only — an attacker simply picks a different LFI target.

---

## Lifecycle

<img src="../../diagrams/lifecycle.svg" alt="security-rust lifecycles: scan, session, throttling" width="900">

Three lifecycles run independently, meeting only in the caller's request handler:
*(Diagram annotations are in Chinese; the labels are API names.)*

| Lifecycle | Starts at | Ends at | State lives in |
|-----------|-----------|---------|----------------|
| **Scan** | `Scanner::scan(&str)` | `Vec<DetectionResult>` → `score::assess` → `RiskAssessment` | Nothing — stateless, independent per call |
| **Session** | `SessionGuard::bind()` writes a `SessionRecord` | `verify()` per request → `SessionVerdict` ⇒ `Allow` / `Challenge` / `Block` | `SessionStore` (built-in `MemoryStore`) |
| **Throttling** | `Throttle::check_any(&[keys])` | `Allow{remaining}` / `Banned{until}` / `Unavailable` | `ThrottleStore` (built-in `MemoryThrottleStore`) |

Two edges that are easy to get wrong:

- **`remaining == 0` means this request should be rejected** — the quota is exhausted, not "one more try left". Don't invert it when writing `X-RateLimit-*` headers.
- **Store failures are handled in opposite directions**: `SessionGuard` is fail-closed (`StoreUnavailable` ⇒ `Block`, never allow — otherwise an attacker who induces a backend failure swaps out a whole class of checks); `Throttle` is fail-open (`Unavailable` is handed to the caller, because locking every user out on a backend blip is self-DoS, and the primary gate `SessionGuard` is still blocking). This is a written design decision, not a missing fallback.

---

## Usage

Ready to use with zero configuration:

```rust
use security_rust::Scanner;

let scanner = Scanner::default();

// Strong signal: the shape can only come from an attack ⇒ the detector's declared severity
let results = scanner.scan("<img src=x onerror=alert(1)>");
// [CRITICAL] XSS cross-site scripting detected — offset: 11, pattern: onerror=

// Weak signal: the token merely appears ⇒ always Low, cannot cross the reject line alone
let weak = scanner.scan("<script src=\"/app.js\"></script>");
// [LOW] XSS tag present (weak signal) — offset: 0, pattern: <script>
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

`verify` returns a `SessionVerdict` rather than a `Result`, because on an auth path "reject" is a normal outcome that callers must handle. The verdict carries a `decision` (`Allow` / `Challenge` / `Block`) and the `threats` behind it. `severity` is an `Option<Severity>`, and a clean allow leaves it at `None`: no finding means no severity, and a stand-in low value would read in the logs exactly like a real low-severity hit.

`RequestContext::subject` is used by `bind` only — `verify` ignores it entirely. The identity checked on every request always comes from the server-side `SessionRecord` (foreign-location history aggregates on `record.subject`), so a subject supplied by the request is not trusted; passing `subject: ""` from middleware is valid. Never put a user identifier from a request header in this field as if it were an identity: it cannot reach the decision today, and a future refactor is not bound to keep it that way.

`bind` and `verify` return `Decision::Block` on a store failure rather than allowing the request through: failing open on a backend error is a bypass an attacker can trigger deliberately.

### Rate Limiting and Banning

```rust
use security_rust::throttle::{MemoryThrottleStore, Throttle, ThrottleConfig, ThrottleDecision, ThrottleOutcome};

let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());
let now = 1_700_000_000;

// A fresh key has the full budget. A real request has two dimensions (IP and
// account); `check_any` queries them in one call and merges by strictness.
assert_eq!(
    throttle.check_any(&["ip:203.0.113.7", "acct:user-42"], now),
    ThrottleDecision::Allow { remaining: 5 }
);

// Each failed login consumes one attempt; the 5th returns Banned, not Allow { remaining: 0 }.
for _ in 0..4 {
    throttle.record_failure("acct:user-42", now).unwrap();
}
assert_eq!(
    throttle.record_failure("acct:user-42", now).unwrap(),
    ThrottleOutcome::Banned { until: now + 900 }
);
```

`Allow { remaining: 0 }` means the request should be **rejected** — the budget is spent, not "one more try left". It is not reported as `Banned` because no ban is in effect at that moment (with `ban_secs = 0`, a drained key stays in this arm forever).

`Throttle` deliberately does **not** fail closed, unlike `SessionGuard`. A store failure yields `ThrottleDecision::Unavailable`, never `Banned`: rate limiting is defense in depth, and locking every user out on a backend blip would be a self-inflicted DoS, whereas allowing traffic only loses brute-force protection for that window. The caller decides what to do — allowing with an alert is the expected choice.

Keys are caller-constructed (`format!("ip:{ip}")`, `format!("acct:{user}")`) and must be normalized and non-empty: handing raw request values straight to `check` lets an attacker split into unlimited buckets by varying the value, and an empty key puts every failed request in one bucket.

See the [API Reference](./API.md) for the complete API documentation (installation, selective scanning, custom configuration, risk scoring, severity display, session security, throttling, performance).

---

## Development

```bash
# Build
cargo build --release

# Tests (580: 431 unit + 148 integration + 1 doc test)
cargo test

# End-to-end pipeline example (scan → throttle → session → action)
cargo run --example waf

# Lints
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
