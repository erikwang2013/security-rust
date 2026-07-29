<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# attack-detection

[English](#english) | **中文**

Rust 编写的攻击检测库，覆盖注入攻击、协议攻击、数据/序列化攻击、文件/敏感数据泄露 4 大类共 27 个检测器。零外部框架依赖，纯字符串扫描。

---

## 设计思路

### 为什么用「检测」而非「拦截」

本库定位为**纯输入扫描器**——接收字符串，返回结构化检测结果。不绑定任何 Web 框架，不做 HTTP 请求/响应解析，不实现实时阻断。这样你可以把它嵌入到任何链路中：WAF 规则引擎、日志审计、API 网关前置校验、CLI 安全扫描工具等。

### 架构原则

- **单一职责** — 每个检测器只管一种攻击类型，内部持有编译好的正则模式集
- **统一接口** — `Detector` trait 是所有检测器的唯一契约：`fn detect(&self, input: &str) -> Option<DetectionResult>`
- **默认覆盖** — `Scanner::default()` 一键装配全部 27 个检测器，零配置可用
- **可选配置** — `Scanner::builder()` 支持按需定制，通过 `.with_detector()` 选择性装配检测器

### 权衡

| 决策 | 选择 | 理由 |
|------|------|------|
| 正则 vs 解析器 | 正则 | 检测场景下速度优先，正则对变形/绕过模式的覆盖更好 |
| 先到先报 vs 全量检测 | 全量检测 | 一个输入可能同时触发多种攻击，不应漏报 |
| 零依赖 vs 引入 serde | 零依赖 | 只依赖 `regex` + `thiserror`，编译快、体积小 |

---

## 设计架构

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

### 模块职责

| 模块 | 路径 | 检测器数 | 职责 |
|------|------|---------|------|
| 核心 | `src/lib.rs` `result.rs` `scanner.rs` | — | `Detector` trait、`DetectionResult`、`Scanner`/`ScannerBuilder` |
| 注入 | `src/injection/` | 10 | XSS、SQL 注入、命令注入、NoSQL、LDAP、XPATH、JNDI、SSI、GraphQL、SSTI |
| 协议 | `src/protocol/` | 9 | SSRF、XXE、Header 注入、Host 头攻击、请求走私、开放重定向、CORS、WebSocket、DNS 重绑定 |
| 数据 | `src/data/` | 5 | PHP 反序列化、CSV 公式注入、邮件头注入、JWT 攻击、原型污染 |
| 文件 | `src/file/` | 3 | 路径遍历、恶意文件上传、敏感数据泄露 |

### 检测结果结构

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

---

## 实现功能

### 注入类攻击（10 个检测器）

| 检测器 | 覆盖模式 | 严重度 |
|--------|---------|--------|
| **xss** | `<script>`、`onerror=` 等事件处理器、`javascript:` 伪协议、`<svg>`/`<iframe>` 标签、CSS `expression()`、`eval()`、`document.cookie` | Critical |
| **sql_injection** | `UNION SELECT`、`sleep()`/`benchmark()`/`pg_sleep()` 延时注入、`information_schema` 枚举、`exec sp_`/`xp_` 存储过程、布尔盲注模式 `' OR '1'='1`、`LOAD_FILE()`/`INTO OUTFILE` | Critical |
| **command_injection** | 反引号命令、`$()` 子命令、管道符链式执行、`/dev/tcp` 反弹 shell、`passthru()`/`shell_exec()`/`system()` PHP 函数、`cmd.exe`/`powershell` 调用 | Critical |
| **nosql_injection** | MongoDB `$ne`/`$gt`/`$regex`/`$where` 操作符、`$or` 注入、认证绕过 `{"$gt": ""}` | Critical |
| **ldap_injection** | `(&` `(|` `(!` 过滤操作符、`*(cn=` 属性枚举、`objectClass`/`uid` 注入 | High |
| **xpath_injection** | `' or '1'='1` 布尔绕过、`' or true()` 函数注入、`'] | '` 节点遍历 | High |
| **jndi_injection** | `${jndi:ldap://`、`${lower:j}` 混淆、`${upper:j}` 混淆、`${::-j}` 空字符串混淆、`${env:}` 环境变量查找、`${sys:}` 系统属性 | Critical |
| **ssi_injection** | `<!--#exec cmd=` 命令执行、`<!--#include file=` 文件包含、`<!--#echo var=` 变量输出、`<!--#fsize`/`<!--#flastmod` 文件信息 | High |
| **graphql_injection** | `__schema`/`__type` 内省查询、深度嵌套 DoS（≥5层） | Medium |
| **ssti** | Jinja2 `{{}}`、FreeMarker `${}`、ERB `<%=` `<%@`、Velocity `#set()`、Python MRO `__mro__`/`__subclasses__()` 沙箱逃逸 | Critical |

### 协议与请求攻击（9 个检测器）

| 检测器 | 覆盖模式 | 严重度 |
|--------|---------|--------|
| **ssrf** | `169.254.169.254` 云元数据、RFC1918 内网 IP（10.x、172.16-31.x、192.168.x）、`127.x` loopback、`::1` IPv6 loopback、`0.0.0.0`、`gopher://`/`dict://`/`ftp://`/`file://` 危险协议 | Critical |
| **xxe** | `<!ENTITY` 实体声明、`SYSTEM`/`PUBLIC` 外部引用、`%` 参数实体、`<!DOCTYPE` DTD 声明 | Critical |
| **header_injection** | `%0d%0a` URL 编码 CRLF、`\r\n` 原始 CRLF 注入 | High |
| **host_header** | 多 Host 头注入、`X-Forwarded-Host`/`X-Original-URL`/`X-Rewrite-URL` 投毒、CRLF 携带 Host | High |
| **request_smuggling** | 双重 `Transfer-Encoding` 头、`Content-Length: 0` 走私、`\r\n0\r\n` chunked 终止混淆 | High |
| **open_redirect** | `//evil.com` 协议相对 URL、`javascript:`/`data:text/html` 伪协议跳转 | Medium |
| **cors** | `Origin: null` 绕过、`Access-Control-Allow-Origin: *` + Credentials 组合 | Medium |
| **websocket** | `Upgrade: websocket` 握手、`Origin: null` 跨域 WS、`ws://` 明文连接 | High |
| **dns_rebinding** | Host 头为 `127.x`/`10.x`/`192.168.x`/`172.16-31.x` 内网 IP、`localhost`、`::1`、`0.0.0.0` | High |

### 数据与序列化攻击（5 个检测器）

| 检测器 | 覆盖模式 | 严重度 |
|--------|---------|--------|
| **deserialization** | PHP `O:数字:`/`C:数字:` 序列化对象、`a:数字:{` 数组、`unserialize()` 调用、`__wakeup`/`__destruct`/`__toString` 等魔术方法 | Critical |
| **csv_injection** | 行首 `=`/`+`/`-`/`@` 公式字符、DDE 动态数据交换、`cmd|` 命令管道、`@SUM()` 函数 | Medium |
| **mail_header** | `Bcc:`/`Cc:` 密送注入、`From:` 多重发件人、`MIME-Version:`/`Content-Type: multipart` MIME 头注入、`boundary=` 边界操纵 | Medium |
| **jwt_attack** | `alg: none` 空算法绕过、`kid` 路径遍历注入、空签名段、空 payload 段 | High |
| **prototype_pollution** | `__proto__`/`constructor.prototype` 原型链污染、`__defineGetter__`/`__defineSetter__`/`__lookupGetter__`/`__lookupSetter__` 属性劫持 | High |

### 文件与敏感数据（3 个检测器）

| 检测器 | 覆盖模式 | 严重度 |
|--------|---------|--------|
| **path_traversal** | `../`/`..\\` 目录跨越、`%2e%2e` URL 编码绕过、`php://filter`/`php://input`/`phar://`/`zip://`/`data://`/`expect://`/`glob://` 协议包装器、`%00` 空字节截断 | Critical |
| **upload** | `<?php`/`<?=` PHP 标签、`<%@`/`<%=` ASP 标签、`eval($_`/`system($_`/`exec($_`/`passthru($_` 后门模式、`$_GET`/`$_POST`/`$_REQUEST`/`$_SERVER` 超全局变量、`base64_decode()` 编码绕过 | Critical |
| **data_leak** | 16 位信用卡 PAN（Visa/MasterCard/AmEx/Discover/JCB/Diners）、AWS Access Key `AKIA...`、PEM 私钥头 `-----BEGIN`、OpenAI/LLM API Key `sk-...`、数据库连接串 `mongodb://`/`mysql://`/`postgresql://`/`redis://`/`jdbc:`、JWT Token | Critical |

---

## 使用说明

### 安装

```toml
[dependencies]
attack-detection = { path = "." }
```

### 快速开始

```rust
use attack_detection::Scanner;

fn main() {
    // 零配置：装配全部 27 个检测器
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
use attack_detection::injection::{XssDetector, SqlInjectionDetector};

// 通过 builder 只装配需要的检测器
let scanner = Scanner::builder()
    .with_detector(Box::new(XssDetector))
    .with_detector(Box::new(SqlInjectionDetector))
    .build();
```

### 只装配部分检测器

```rust
use attack_detection::injection::{XssDetector, SqlInjectionDetector};

let scanner = Scanner::builder()
    .with_detector(Box::new(XssDetector))
    .with_detector(Box::new(SqlInjectionDetector))
    .build();
```

### 严重度展示

```rust
use attack_detection::Severity;

let r = &results[0];
println!("{}", r.severity);  // CRITICAL | HIGH | MEDIUM | LOW
```

### 性能

Release 构建下，单检测器扫描 ~100ns/次（RegexSet 预编译），全量 27 检测器扫描约 ~5μs/次。适合高吞吐量场景（API 网关、日志管道）。

---

## 开发

```bash
# 构建
cargo build --release

# 测试（46 个集成测试）
cargo test

# 代码检查
cargo clippy -- -D warnings
```

---

## 许可

MIT — Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

---

## English

**Full English documentation is available at [README.en.md](./README.en.md).**

A pure Rust attack detection library with 27 detectors across 4 categories. Zero framework dependencies — just `regex` and `thiserror`.

**Categories:** Injection (10), Protocol (9), Data (5), File (3).

Key API surfaces are in English (type names, method names, error messages).
