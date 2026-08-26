<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust

**🌐 Language:** [English](./docs/i18n/en/README.md) · [한국어](./docs/i18n/ko/README.md) · [Русский](./docs/i18n/ru/README.md) · [Deutsch](./docs/i18n/de/README.md) · [Français](./docs/i18n/fr/README.md) · [Español](./docs/i18n/es/README.md) · [Português](./docs/i18n/pt/README.md) · [हिन्दी](./docs/i18n/hi/README.md) · [العربية](./docs/i18n/ar/README.md) · [বাংলা](./docs/i18n/bn/README.md) · [Bahasa Indonesia](./docs/i18n/id/README.md) · [日本語](./docs/i18n/ja/README.md)

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

`DetectionResult` 结构化返回 `attack_type`、`category`、`severity`、`matched_pattern`、`offset`、`message` 六项字段。完整定义见 [API 参考](./docs/API.md)。

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

零配置即可使用：

```rust
use security_rust::Scanner;

let scanner = Scanner::default();
let results = scanner.scan("<script>alert('xss')</script>");
// [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
```

完整 API 参考（安装、选择性扫描、自定义配置、严重度展示、性能）见 [API 参考](./docs/API.md)。

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

## 打赏 / 赞助

如果这个项目对你有帮助，欢迎打赏支持（自愿）。

| 支付宝 | 微信支付 |
|--------|---------|
| ![支付宝](docs/alipay.png) | ![微信支付](docs/weixinpay.png) |

### 全球转账（国际汇款）

【收款人信息】
- 收款人姓名：WANG KEXUN
- 收款账户号码：881015918251

【收款银行】
- ZA Bank SWIFT Code：AABLHKHHXXX
- 银行名称：ZA Bank Limited
- 银行编号：387
- 银行地址：Core F, Cyberport 3, 100 Cyberport Road, Hong Kong

【跨境汇款代理银行（如需）】

请留意，此为跨境汇款代理银行（中转银行）信息，非收款银行信息。请向汇款银行查询是否需要提供跨境汇款代理银行信息。

汇入港元、人民币及美元的代理银行为 Citibank：
- 银行名称：Citibank N.A. Hong Kong
- SWIFT Code：CITIHKHXXXX
- 银行编号：006
- 分行名称：Hong Kong Branch
- 分行编号：391
- 银行地址：Citibank Tower, Citibank Plaza, 3 Garden Road, Central, Hong Kong

汇入其他币种时的代理银行为 BNY Mellon：
- 银行名称：THE BANK OF NEW YORK MELLON
- SWIFT Code：IRVTUS3NXXX
- 银行地址：THE BANK OF NEW YORK MELLON, 240 GREENWICH STREET, NEW YORK, United States

---

## 许可

MIT — Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
