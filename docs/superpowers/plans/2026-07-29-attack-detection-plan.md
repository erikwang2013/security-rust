<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# Attack Detection Library — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a pure Rust attack detection library with 27 detectors across 4 categories, consuming string input and returning structured `DetectionResult` values.

**Architecture:** Single crate with `Detector` trait as the common interface. Each detector is a struct holding compiled regex patterns. A `Scanner` aggregates all detectors and runs them in sequence, returning all matches. Builder pattern for optional configuration.

**Tech Stack:** Rust 2024 edition, `regex` crate, `thiserror` crate

---

### Task 1: Project scaffold

**Files:**
- Create: `Cargo.toml`
- Create: `src/lib.rs`
- Create: `src/result.rs`

- [ ] **Step 1: Write Cargo.toml**

```toml
[package]
name = "attack-detection"
version = "0.1.0"
edition = "2024"

[dependencies]
regex = "1"
thiserror = "2"
```

- [ ] **Step 2: Write core types in src/result.rs**

```rust
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttackCategory {
    Injection,
    Protocol,
    Data,
    File,
}

#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub attack_type: String,
    pub category: AttackCategory,
    pub severity: Severity,
    pub matched_pattern: String,
    pub offset: usize,
    pub message: String,
}
```

- [ ] **Step 3: Define Detector trait in src/lib.rs**

```rust
pub mod result;
mod injection;
mod protocol;
mod data;
mod file;
mod scanner;

pub use result::{AttackCategory, DetectionResult, Severity};

pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
    fn detect(&self, input: &str) -> Option<DetectionResult>;
}
```

- [ ] **Step 4: Create module directories**

```bash
mkdir -p src/injection src/protocol src/data src/file
```

Each `mod.rs` re-exports its detectors.

- [ ] **Step 5: Verify build**

Run: `cargo build`
Expected: Compiles

- [ ] **Step 6: Commit**

---

### Task 2: Scanner and ScannerBuilder

**Files:**
- Create: `src/scanner.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Write scanner.rs with Scanner struct and ScannerBuilder**

Scanner holds `Vec<Box<dyn Detector>>`, provides `default()`, `builder()`, `scan()`, `scan_with()`.

ScannerBuilder supports: `with_detector()`, `build()`.

- [ ] **Step 2: Update lib.rs** — add `pub mod scanner; pub use scanner::{Scanner, ScannerBuilder};`

- [ ] **Step 3: Verify build** — `cargo build`

- [ ] **Step 4: Commit**

---

### Task 3: XSS detector

**Files:**
- Create: `src/injection/xss.rs`
- Modify: `src/injection/mod.rs`

Patterns (case-insensitive): `<script[\s/>]`, `on[a-z]+\s*=`, `javascript\s*:`, `<svg[\s/>]`, `expression\s*\(`, `<iframe[\s/>]`, `<embed[\s/>]`, `<object[\s/>]`, `vbscript\s*:`, `data\s*:\s*text/html`, `<link[\s/>]`, `<meta[\s/>]`, `eval\s*\(`, `fromCharCode\s*\(`, `document\.cookie`, `document\.write\s*\(`, `window\.location`

- [ ] **Verify build and commit**

---

### Task 4: SQL Injection detector

**Files:**
- Create: `src/injection/sql_injection.rs`
- Modify: `src/injection/mod.rs`

Patterns: `UNION\s+(?:ALL\s+)?SELECT`, `SELECT\s+.*\s+FROM`, `/\*!.*?\*/`, `sleep\s*\(`, `benchmark\s*\(`, `pg_sleep\s*\(`, `information_schema`, `exec\s+(?:sp_|xp_)`, `WAITFOR\s+DELAY`, `'\s*OR\s*'1'\s*=\s*'1`, `LOAD_FILE\s*\(`, `INTO\s+(?:OUT|DUMP)FILE`, `OUTFILE\s+`

---

### Task 5: Command Injection detector

**Files:**
- Create: `src/injection/command_injection.rs`
- Modify: `src/injection/mod.rs`

Patterns: backtick commands, `\$\([^)]+\)`, pipe chaining, `/dev/tcp`, `passthru\(`, `shell_exec\(`, `system\(`, `exec\(`, `popen\(`, `pcntl_exec\(`, `cmd\.exe`, `powershell`, `>\/dev\/null`

---

### Task 6: NoSQL Injection detector

**Files:**
- Create: `src/injection/nosql_injection.rs`
- Modify: `src/injection/mod.rs`

Patterns: `"\$ne"\s*:`, `"\$gt"\s*:`, `"\$regex"\s*:`, `"\$where"\s*:`, `"\$or"\s*:`, `\$eq`, `\$nin`, auth bypass pattern

---

### Task 7: LDAP Injection detector

**Files:**
- Create: `src/injection/ldap_injection.rs`
- Modify: `src/injection/mod.rs`

Patterns: `\(\s*&`, `\(\s*\|`, `\(\s*!`, `\*\(cn=`, `\(\s*objectClass\s*=`, `\(\s*uid\s*=`

---

### Task 8: XPath Injection detector

**Files:**
- Create: `src/injection/xpath_injection.rs`
- Modify: `src/injection/mod.rs`

Patterns: `'\s*or\s*'1'\s*=\s*'1`, `'\s*and\s*'1'\s*=\s*'2`, `'\s*or\s*1\s*=\s*1`, `"\s*or\s*"1"\s*=\s*"1`

---

### Task 9: JNDI/Log4Shell detector

**Files:**
- Create: `src/injection/jndi_injection.rs`
- Modify: `src/injection/mod.rs`

Patterns: `\$\{jndi:`, `\$\{lower:j\}`, `\$\{upper:j\}`, `\$\{::-j\}`, `\$\{env:`, `\$\{sys:`, `\$\{java:`, `ldap://`, `rmi://`, `dns://`

---

### Task 10: SSI, GraphQL, SSTI detectors

**Files:**
- Create: `src/injection/ssi_injection.rs`
- Create: `src/injection/graphql_injection.rs`
- Create: `src/injection/ssti.rs`
- Modify: `src/injection/mod.rs`

SSI: `<!--#exec cmd=`, `<!--#include file=`, `<!--#echo var=`
GraphQL: `__schema`, `__type`, deep nested query detection
SSTI: `\{\{.*?\}\}`, `\$\{.*?\}`, `<%=`, `__mro__`, `__subclasses__`, `__globals__`, `__builtins__`

---

### Task 11: SSRF detector

**Files:**
- Create: `src/protocol/ssrf.rs`
- Create: `src/protocol/mod.rs`
- Modify: `src/lib.rs` — `pub mod protocol;`

Patterns: `169\.254\.169\.254`, RFC1918 IPs, `127.*`, `::1`, `0.0.0.0`, `gopher://`, `dict://`, `ftp://`, `file://`

---

### Task 12: XXE detector

**Files:**
- Create: `src/protocol/xxe.rs`
- Modify: `src/protocol/mod.rs`

Patterns: `<!ENTITY\s+`, `SYSTEM\s+["']`, `PUBLIC\s+["']`, `<!ENTITY\s+%`, `<!DOCTYPE\s+`

---

### Task 13: Header Injection, Host Header, Request Smuggling

**Files:**
- Create: `src/protocol/header_injection.rs`
- Create: `src/protocol/host_header.rs`
- Create: `src/protocol/request_smuggling.rs`
- Modify: `src/protocol/mod.rs`

---

### Task 14: Open Redirect, CORS, WebSocket, DNS Rebinding

**Files:**
- Create: `src/protocol/open_redirect.rs`
- Create: `src/protocol/cors.rs`
- Create: `src/protocol/websocket.rs`
- Create: `src/protocol/dns_rebinding.rs`
- Modify: `src/protocol/mod.rs`

---

### Task 15: PHP Deserialization & CSV Injection

**Files:**
- Create: `src/data/deserialization.rs`
- Create: `src/data/csv_injection.rs`
- Create: `src/data/mod.rs`
- Modify: `src/lib.rs` — `pub mod data;`

---

### Task 16: Mail Header, JWT Attack, Prototype Pollution

**Files:**
- Create: `src/data/mail_header.rs`
- Create: `src/data/jwt_attack.rs`
- Create: `src/data/prototype_pollution.rs`
- Modify: `src/data/mod.rs`

---

### Task 17: Path Traversal detector

**Files:**
- Create: `src/file/path_traversal.rs`
- Create: `src/file/mod.rs`
- Modify: `src/lib.rs` — `pub mod file;`

Patterns: `\.\./`, `\.\.\\`, `php://filter`, `php://input`, null byte `%00`, encoded traversal

---

### Task 18: File Upload & Data Leak detectors

**Files:**
- Create: `src/file/upload.rs`
- Create: `src/file/data_leak.rs`
- Modify: `src/file/mod.rs`

Upload: `<\?php`, `<?=`, webshell patterns
Data leak: credit card Luhn, AWS keys, private key headers, `sk-*` tokens, database connection strings

---

### Task 19: Wire up Scanner::default() with all 27 detectors

**Files:**
- Modify: `src/scanner.rs`

Update `Scanner::default()` to instantiate and register all detection structs. Verify build.

---

### Task 20: Integration tests

**Files:**
- Create: `tests/integration_test.rs`

Tests for: xss, sql_injection, command_injection, ssrf, path_traversal, jndi_injection, ssti, data_leak detection + clean input no false positives + scan_with filtering.

---

### Task 21: Final verification

Run `cargo build --release`, `cargo test --release`, `cargo clippy` if available.
