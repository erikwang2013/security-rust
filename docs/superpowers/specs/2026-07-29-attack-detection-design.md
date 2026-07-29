<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# Attack Detection Library — Design Spec

## Overview

纯 Rust 攻击检测库，输入字符串 → 输出结构化检测结果。覆盖注入攻击、协议攻击、数据/序列化攻击、文件/敏感数据 4 大类共 27 个检测器。

## Core Types

```rust
pub enum Severity { Critical, High, Medium, Low }

pub enum AttackCategory { Injection, Protocol, Data, File }

pub struct DetectionResult {
    pub attack_type: String,
    pub category: AttackCategory,
    pub severity: Severity,
    pub matched_pattern: String,
    pub offset: usize,
    pub message: String,
}

pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
    fn detect(&self, input: &str) -> Option<DetectionResult>;
}
```

每个检测器是实现了 `Detector` trait 的结构体，内部持有编译好的正则。支持 Builder 模式配置。

## Module Structure

```
src/
├── lib.rs
├── scanner.rs
├── result.rs
├── injection/
│   ├── mod.rs
│   ├── xss.rs
│   ├── sql_injection.rs
│   ├── command_injection.rs
│   ├── nosql_injection.rs
│   ├── ldap_injection.rs
│   ├── xpath_injection.rs
│   ├── jndi_injection.rs
│   ├── ssi_injection.rs
│   ├── graphql_injection.rs
│   └── ssti.rs
├── protocol/
│   ├── mod.rs
│   ├── ssrf.rs
│   ├── xxe.rs
│   ├── header_injection.rs
│   ├── host_header.rs
│   ├── request_smuggling.rs
│   ├── open_redirect.rs
│   ├── cors.rs
│   ├── websocket.rs
│   └── dns_rebinding.rs
├── data/
│   ├── mod.rs
│   ├── deserialization.rs
│   ├── csv_injection.rs
│   ├── mail_header.rs
│   ├── jwt_attack.rs
│   └── prototype_pollution.rs
└── file/
    ├── mod.rs
    ├── path_traversal.rs
    ├── upload.rs
    └── data_leak.rs
```

## Detector Coverage

### 注入类攻击 (injection/)

| Detector | Key Patterns | Severity |
|----------|-------------|----------|
| xss | `<script`, `on[a-z]+=`, `javascript:`, `<svg`, CSS `expression()` | Critical |
| sql_injection | `UNION SELECT`, `sleep(`, `benchmark(`, `pg_sleep`, `information_schema`, `exec sp_` | Critical |
| command_injection | backtick, `$()`, pipe, `/dev/tcp`, `passthru(`, `shell_exec(` | Critical |
| nosql_injection | `$ne`, `$gt`, `$regex`, `$where`, auth bypass | Critical |
| ldap_injection | `(&`, `(|`, `(!`, `*(cn=` | High |
| xpath_injection | `' or '1'='1`, boolean blind patterns | High |
| jndi_injection | `${jndi:`, `${lower:j}`, `${env:`, `${sys:` | Critical |
| ssi_injection | `<!--#exec cmd=`, `<!--#include file=`, `<!--#echo var=` | High |
| graphql_injection | `__schema`, `__type`, deep nested query | Medium |
| ssti | `{{}}`, `${}`, `<% %>`, `__mro__`, `__subclasses__` | Critical |

### 协议与请求攻击 (protocol/)

| Detector | Key Patterns | Severity |
|----------|-------------|----------|
| ssrf | `169.254.169.254`, internal IPs, `::1`, `gopher://`, `dict://` | Critical |
| xxe | `<!ENTITY`, `SYSTEM "file://`, `PUBLIC "`, parameter entity `%` | Critical |
| header_injection | `%0d%0a`, `\r\n` CRLF | High |
| host_header | Multiple Host, `X-Forwarded-Host`, CRLF in Host | High |
| request_smuggling | TE/CL mismatch, double TE header | High |
| open_redirect | `//evil.com`, `javascript:`, `data:text/html` | Medium |
| cors | `Origin: null`, wildcard + credentials | Medium |
| websocket | `Upgrade: websocket`, cross-origin WS | High |
| dns_rebinding | Host = internal IP, localhost, short hostname | High |

### 数据与序列化攻击 (data/)

| Detector | Key Patterns | Severity |
|----------|-------------|----------|
| deserialization | `O:digit:`, `C:digit:`, `unserialize(` | Critical |
| csv_injection | Leading `=`, `+`, `-`, `@` formula chars | Medium |
| mail_header | `Bcc:`, `Cc:`, `MIME-Version:`, multipart boundary | Medium |
| jwt_attack | `alg: none`, `kid` traversal, empty signature | High |
| prototype_pollution | `__proto__`, `constructor[`, `__defineGetter__` | High |

### 文件与敏感数据 (file/)

| Detector | Key Patterns | Severity |
|----------|-------------|----------|
| path_traversal | `../`, `..\\`, `php://filter`, null byte `%00` | Critical |
| upload | `<?php`, `<?=`, webshell patterns | Critical |
| data_leak | Credit card (Luhn), AWS keys, `-----BEGIN`, `sk-*`, connection strings | Critical |

## Scanner API

```rust
pub struct Scanner { detectors: Vec<Box<dyn Detector>> }

impl Scanner {
    pub fn new() -> Self;
    pub fn builder() -> ScannerBuilder;
    pub fn scan(&self, input: &str) -> Vec<DetectionResult>;
    pub fn scan_with(&self, input: &str, names: &[&str]) -> Vec<DetectionResult>;
}
```

Scanner 实现了 `Default` trait，`Scanner::default()` 返回预装全部 27 个检测器的实例。

## Builder Configuration

```rust
use attack_detection::injection::{XssDetector, SqlInjectionDetector};

let scanner = Scanner::builder()
    .with_detector(Box::new(XssDetector))
    .with_detector(Box::new(SqlInjectionDetector))
    .build();
```

`ScannerBuilder` 支持通过 `with_detector()` 选择性装配检测器，适用于只需要部分检测能力的场景。

## Dependencies

- `regex` — pattern matching
- `thiserror` — error types
- No external framework bindings

## Non-Goals

- 不绑定特定 Web 框架
- 不做 HTTP 请求/响应解析
- 不做实时防护/阻断，只做检测
