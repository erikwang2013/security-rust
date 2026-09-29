<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust

**🌐 Language:** [English](./docs/i18n/en/README.md) · [한국어](./docs/i18n/ko/README.md) · [Русский](./docs/i18n/ru/README.md) · [Deutsch](./docs/i18n/de/README.md) · [Français](./docs/i18n/fr/README.md) · [Español](./docs/i18n/es/README.md) · [Português](./docs/i18n/pt/README.md) · [हिन्दी](./docs/i18n/hi/README.md) · [العربية](./docs/i18n/ar/README.md) · [বাংলা](./docs/i18n/bn/README.md) · [Bahasa Indonesia](./docs/i18n/id/README.md) · [日本語](./docs/i18n/ja/README.md)

Rust 编写的攻击检测库，覆盖注入攻击、协议攻击、数据/序列化攻击、文件/敏感数据泄露 4 大类共 32 个检测器；另提供会话安全、限流封禁、风险评分三个有状态安全模块。零外部框架依赖，`[dependencies]` 只有 `regex`。

项目宠物 **甲哨 Sentri**（[`docs/pet.svg`](./docs/pet.svg)）—— 32 片甲片对应 32 个检测器，只报告，不拦截。

---

## 项目宠物：甲哨 Sentri

<img src="./docs/pet.svg" alt="甲哨 Sentri —— security-rust 项目宠物" width="340">

一只举着放大镜与告示牌的哨蟹。人设不是装饰，是把本库的设计画出来了：

| 形象 | 对应设计 |
|------|---------|
| 甲壳上 4 行 × 8 片甲片 | 32 个无状态检测器；4 行 = 注入 / 协议 / 数据 / 文件四大类 |
| 左钳的放大镜 | 负责**看** —— `Detector::detect()` 只做扫描，命中就返回一条证据 |
| 右钳的告示牌（`已上报`） | 负责**报** —— 返回 `DetectionResult`，不抛异常、不打断调用链 |
| 钳子从不夹人 | 判定权在调用方；唯一例外是 `SessionGuard`，它是真的会 `Block` |
| 单片镜 | 审计员的职业病：每条结论都带 `matched_pattern` 与 `offset`，能落到原文位置 |
| 铭牌上的 `deps: regex ×1` | 零依赖承诺：`[dependencies]` 永远只有 `regex` |

座右铭：**只报告，不拦截。**

形象以 `include_str!` 打进库里（零运行时开销，不用就不链接），ASCII 版可直接打进终端或日志：

```rust
println!("{}", security_rust::pet::ASCII);
```

---

## 项目结构

```
security-rust/
├── src/
│   ├── lib.rs              Detector trait（唯一契约）、regex_detect 辅助、crate 文档
│   ├── scanner.rs          Scanner / ScannerBuilder：默认装配 32 个检测器
│   ├── result.rs           DetectionResult / AttackCategory / Severity
│   ├── score.rs            风险评分：权重累加 + 分档 → RiskAssessment
│   ├── pet.rs              项目宠物形象（NAME / TAGLINE / ASCII / SVG）
│   ├── injection/          11 个注入类检测器
│   ├── protocol/           11 个协议类检测器
│   ├── data/               7 个数据类检测器
│   ├── file/               3 个文件类检测器
│   ├── session/            SessionGuard + SessionStore（guard / store / geo）
│   └── throttle/           Throttle + ThrottleStore（guard / store）
├── tests/                  7 个集成测试套件：会话、限流、生命周期、不变量、鲁棒性、端到端、多维限流
├── examples/
│   ├── waf.rs              端到端流水线示例（扫描 → 限流 → 会话 → 处置）
│   └── axum_middleware.rs  axum 中间件接入参考
├── docs/
│   ├── API.md              完整 API 参考
│   ├── OWASP-COVERAGE.md   与 OWASP 各类攻击的覆盖对照
│   ├── pet.svg             项目宠物形象
│   ├── diagrams/           架构 / 功能 / 生命周期三张图（SVG）
│   ├── i18n/               12 语言 README 与 API 文档
│   └── ...                 打赏码、代码评审与测试报告
└── Cargo.toml              唯一的运行时依赖：regex
```

---

## 设计思路

### 为什么用「检测」而非「拦截」

32 个检测器定位为**纯输入扫描器**——接收字符串，返回结构化检测结果，不绑定任何 Web 框架，不做 HTTP 请求/响应解析。这样你可以把它嵌入到任何链路中：WAF 规则引擎、日志审计、API 网关前置校验、CLI 安全扫描工具等。

会话安全（`session`）与限流封禁（`throttle`）是**有状态、身份相关**的，因此与检测器分开：它们要读写的输入是「token + 指纹 + 位置 + 时间」这类复合值，还要访问存储后端，`Detector::detect(&str)` 表达不了，所以**不实现 `Detector` trait**。两者的共同点仍是「不替你拦截」——`session` 给处置建议、`throttle` 给额度与封禁状态，是否拒绝请求由调用方决定。

### 架构原则

- **单一职责** — 每个检测器只管一种攻击类型，内部持有编译好的正则模式集
- **统一接口** — `Detector` trait 是所有检测器的唯一契约：`fn detect(&self, input: &str) -> Option<DetectionResult>`
- **默认覆盖** — `Scanner::default()` 一键装配全部 32 个检测器，零配置可用
- **可选配置** — `Scanner::builder()` 支持按需定制，通过 `.with_detector()` 选择性装配检测器
- **状态外置** — `session` / `throttle` 用 `SessionStore` / `ThrottleStore` trait 抽象存储，多实例部署实现该 trait 接 Redis 即可，库自身不绑定任何后端
- **零新增依赖** — `[dependencies]` 始终只有 `regex = "1"`：token 与签名由调用方提供，位置由调用方解析
- **fail-closed 是默认，例外要说明理由** — `SessionGuard` 在存储后端故障时返回 `Decision::Block`，绝不放行；`Throttle` 是唯一例外，故障时返回 `Unavailable` 交调用方处置

### 权衡

| 决策 | 选择 | 理由 |
|------|------|------|
| 正则 vs 解析器 | 正则 | 检测场景下速度优先，正则对变形/绕过模式的覆盖更好 |
| 先到先报 vs 全量检测 | 全量检测 | 一个输入可能同时触发多种攻击，不应漏报 |
| 零依赖 vs 引入 serde | 零依赖 | `[dependencies]` 只有 `regex`，编译快、体积小 |
| 检测器 vs 有状态模块 | 分开 | `Detector::detect(&str)` 只有字符串入参，表达不了「token + 指纹 + 位置 + 时间」的复合输入，`session` / `throttle` 因此独立于 `Scanner` |
| fail-closed vs fail-open | 认证 fail-closed，限流 fail-open | 会话判定放行等于被绕过，必须阻断；限流挡全体用户是自我 DoS，且主认证闸门仍在拦，处置权交调用方 |

### 两档判定：强信号与弱信号

检测器**不是**「命中即按声明严重度上报」。32 个检测器里有 18 个把模式分成两档（源码里的 `STRONG_PATTERNS` / `WEAK_PATTERNS`）：

| 档位 | 判据 | 上报严重度 | 单条能否越过拒绝线 |
|------|------|-----------|------------------|
| **强信号** | 形态本身只可能来自攻击 | 检测器声明的等级 | 能 |
| **弱信号** | 该 token「出现」而已，正常内容里遍地都是 | 固定 `Severity::Low`（5 分） | **不能** |

两档走的是同一个检测器、同一个 `attack_type`，只有 `severity` 不同。弱信号**仍然被检出**，不会静默漏报：`scan()` 里看得到，`assess()` 里照常累加。

对调用方的直接后果是：**单条弱信号不构成拒绝理由。** 参考流水线（[`examples/waf.rs:166`](./examples/waf.rs)）的拒绝线是 `risk.level >= RiskLevel::High`（40 分），而单条弱信号只有 5 分，进不了这一支。要看穿弱信号背后的攻击，得看 `assess()` 把多个检测器的命中叠起来之后的分数：

```rust
let scanner = Scanner::default();

// 三条都是弱信号，各自命中不同的检测器 —— 叠起来才升级
let a = scanner.assess("<script src=\"/app.js\"></script>\n../config\n__proto__");
// a.results == 3，a.score == 15（3 × Low）→ RiskLevel::Medium
// 仍低于 High；同一请求里再叠加别的命中就会越线
```

被降为弱信号的是「出现即正常」的那类 token，例如：

| 弱信号 | 为什么不能单独拒绝 |
|--------|-------------------|
| `<script src=...>`、`<iframe>`、`<link>`、`expression(` | 每个网页都有 |
| 单级 `../` | 每份源码里的相对路径 |
| 行首 `-2`、`+1` | Markdown 列表项、散文里的负数 |
| 裸 `__proto__`（读原型） | 任何碰原型链的 JS |
| `${env:}` / `${sys:}` | log4j2 的合法配置语法 |
| `X-Forwarded-Host`、`X-Original-URL` | 反向代理自己就会加 |
| `Host: 10.244.1.5`、`Host: localhost` | k8s pod 互调、本地开发 |
| 裸 `10.0.0.5`、`192.168.1.1`、`127.0.0.1` | `X-Forwarded-For`、`bind 127.0.0.1` |
| `//evil.com` 协议相对 URL | 源码注释、文档里的 CDN 链接 |
| `information_schema` | PG 报错日志、SQL 教程 |

上表只是举例。判据是**形态**不是文件名：同样是 `../`，单级 `../x` 是弱信号、多级 `../../` 是强信号（[`src/file/path_traversal.rs`](./src/file/path_traversal.rs)）。完整名单见各检测器的 `WEAK_PATTERNS`，以及下节各表中的 `弱` 标记。

---

## 设计架构

<img src="./docs/diagrams/architecture.svg" alt="security-rust 架构图：调用方 → 检测层 → 评分层 → 守卫层 → 存储层" width="900">

五层自上而下：**调用方**（WAF / 网关 / 审计 / CLI）→ **检测层**（`Scanner` 持有 `Vec<Box<dyn Detector>>`，四大类共 32 个）→ **评分层**（`score::assess`）→ **守卫层**（`SessionGuard` / `Throttle`，各自绑定一个 store trait）→ **存储抽象**（内置 `MemoryStore`，Redis 由调用方实现）。

`Detector` trait 是检测层唯一的契约：`fn detect(&self, input: &str) -> Option<DetectionResult>`。`session` / `throttle` / `score` 不实现它 —— 它们要么输入不是单个字符串（token + 指纹 + 位置 + 时间），要么消费的是扫描结果而非原始输入，因此各自独立作答（详见下节）。图中右侧那条红色回传线是本库的边界：**判定结果交回调用方执行**，库自己不碰请求。

### 模块职责

| 模块 | 路径 | 检测器数 | 职责 |
|------|------|---------|------|
| 核心 | `src/lib.rs` `result.rs` `scanner.rs` | — | `Detector` trait、`DetectionResult`、`Scanner`/`ScannerBuilder` |
| 注入 | `src/injection/` | 11 | XSS、SQL 注入、命令注入、NoSQL、LDAP、XPATH、JNDI、SSI、GraphQL、SSTI、格式串注入 |
| 协议 | `src/protocol/` | 11 | SSRF、XXE、Header 注入、Host 头攻击、请求走私、开放重定向、CORS、WebSocket、DNS 重绑定、Log4Shell、HTTP 参数污染 |
| 数据 | `src/data/` | 7 | PHP 反序列化、CSV 公式注入、邮件头注入、JWT 攻击、原型污染、表格公式注入、ReDoS |
| 文件 | `src/file/` | 3 | 路径遍历、恶意文件上传、敏感数据泄露 |
| 会话 | `src/session/` | — | `SessionGuard`：客户端劫持、数据篡改、异地登录 / 不可能旅行、token 会话绑定与吊销 |
| 限流 | `src/throttle/` | — | `Throttle`：滑动窗口计数、阈值封禁、账户锁定 |
| 评分 | `src/score.rs` | — | `RiskAssessment`：把多条低危命中聚合成可观测量 |

`session` 与 `throttle` 是**有状态**的，不对应任何检测器：它们不在 `Scanner` 的装配范围内，也不能用 `scan()` 调用。

### 检测结果结构

`DetectionResult` 结构化返回 `attack_type`、`category`、`severity`、`matched_pattern`、`offset`、`message` 六项字段。`Scanner::assess()` 在此之上给出聚合后的风险等级（`RiskAssessment`）。完整定义见 [API 参考](./docs/API.md)。

---

## 实现功能

<img src="./docs/diagrams/features.svg" alt="security-rust 功能图：注入 11、协议 11、数据 7、文件 3，加三个有状态模块" width="900">

32 个检测器按四大类装配，`Scanner::default()` 零配置全量启用；下表逐个列出各自覆盖的攻击模式与严重度。严重度只描述单条命中的危害，聚合后的整体风险看 `Scanner::assess()`。

表内标注 `弱` 的模式属**弱信号**，上报 `Severity::Low`（5 分），不单独越过拒绝线（详见上节）。「严重度」一列为该检测器能达到的**上限**；标了 `弱` 的检测器同时存在强档与弱档，上半部分仍是其声明的等级。全档皆弱的检测器（`dns_rebinding`）上限即为 `Low`。

### 注入类攻击（11 个检测器）

| 检测器 | 覆盖模式 | 严重度 |
|--------|---------|--------|
| **xss** | `onerror=`/`onload=` 等事件处理器全表、`javascript:`/`vbscript:` 伪协议（只认 scheme 后紧跟非空白）；`弱`：`<script src=...>`/`<iframe>`/`<embed>`/`<object>`/`<link>` 标签、CSS `expression(` | Critical |
| **sql_injection** | `UNION SELECT`、`sleep()`/`benchmark()`/`pg_sleep()` 延时注入（限语句位置）、`exec sp_`/`xp_` 存储过程、布尔盲注模式 `' OR '1'='1`、`LOAD_FILE()`/`INTO OUTFILE`、`DROP TABLE`/`INSERT INTO`、注释符拆词 `UN/**/ION`；`弱`：`information_schema` 词出现 | Critical |
| **command_injection** | `/dev/tcp` 反弹 shell、`passthru()`/`shell_exec()`/`system("…")`/`popen()`/`pcntl_exec()` 调用形态、`powershell -Command`/`cmd.exe /c` 调用形态；`弱`：反引号 span、`$()` 子命令、管道符/`\|\|`/`&&` 链式执行、`exec(`、`>/dev/null`、`cat /etc/passwd` 这类 reader+路径、裸 `cmd.exe`/`powershell` 词 | Critical |
| **nosql_injection** | MongoDB `$ne`/`$gt`/`$regex`/`$where` 操作符、`$or` 注入、认证绕过 `{"$gt": ""}` | Critical |
| **ldap_injection** | `(&` `(\|` `(!` 过滤操作符、`*(cn=` 属性枚举、`objectClass`/`uid` 注入 | High |
| **xpath_injection** | `' or '1'='1` 布尔绕过、`' or true()` 函数注入、`'] \| '` 节点遍历 | High |
| **jndi_injection** | `${jndi:` 查找本体、`${lower:j}`/`${upper:j}` 大小写折叠、`${::-j}` 空字符串折叠（只为混淆 `jndi` 而存在）；`弱`：`${env:}`/`${sys:}`/`${java:}` 合法 lookup 语法 | Critical |
| **ssi_injection** | `<!--#exec cmd=` 命令执行、`<!--#include file=` 带绝对路径或 `..` 的包含、`<!--#printenv` 环境导出；`弱`：`<!--#echo var=` 变量输出、`<!--#fsize`/`<!--#flastmod` 文件信息、`<!--#config`、`<!--#include file="header.html"` 这类常规包含 | High |
| **graphql_injection** | `__schema {`/`__type {` 带选择集的内省查询（散文里提到字段名不报）；`弱`：`__typename`（Apollo/Relay 自动加进每条查询）、≥5 层嵌套花括号 | Medium |
| **ssti** | Jinja2 `{{ }}` / FreeMarker `${ }` **定界符内的求值**（`{{7*7}}`、`${7*7}`、`{{config`、`${T(java.lang.Runtime)}`、`${@Type@method}`）、`{% include '/…'` / `..` 的模板 LFI、定界符内的逃逸链 `__mro__`/`__subclasses__()`/`__globals__`/`__builtins__`/`__class__`/`__dict__`、FreeMarker `?new(`；`弱`：`{% %}`、`<%=`/`<%@`、`#set(` 等裸模板指令、裸魔术属性；定界符本身不是信号，`${x}` 这类纯占位符不报 | Critical |
| **format_string** | `%n`/`%hn`/`%1$n` 内存写入转换符、`%99999999d` 超宽宽度炸弹、`%x%x%x`/`%p%p%p` 连续读栈、`%08x.%08x` 带分隔泄露、连续 4 个以上 `%s` 逐栈读取；单个 `%s`/`%d` 属正常占位符不报 | Medium |

### 协议与请求攻击（11 个检测器）

| 检测器 | 覆盖模式 | 严重度 |
|--------|---------|--------|
| **ssrf** | `169.254.169.254` 云元数据与 `metadata.google.internal`（不要求 URL 上下文）、**URL authority 位置**（`//` 之后）的内网 IP `10.x`/`172.16-31.x`/`192.168.x`/`127.x`、`//localhost`、`//0.0.0.0`、`//[::1]`、危险协议 `gopher://`/`dict://`/`ftp://user@`/`file:///`；`弱`：**非 URL 位置**的同一批内网字面量（`X-Forwarded-For: 10.0.0.5`、`bind 127.0.0.1`、`{"host": "10.0.0.1"}` 逐字节同形） | Critical |
| **xxe** | `<!ENTITY` 实体声明、`SYSTEM`/`PUBLIC` 外部引用、`%` 参数实体、`<!DOCTYPE` DTD 声明 | Critical |
| **header_injection** | 响应专有头前置 `\r\n`：`Set-Cookie`/`Location`/`Refresh`/`Status`/`WWW-Authenticate`、`%0d` 与 `%0a` 同现（含反序 `%0a…%0d`）。`Content-Length`/`Content-Type`/`Transfer-Encoding` 是**请求**头，与正常报文的每个头逐字节同形，不再作为信号（编码形态 `%0d%0aContent-Length:` 仍由 `%0d`+`%0a` 覆盖） | High |
| **host_header** | **两个** `Host:` 头（RFC 7230 §5.4 要求一律回 400，两层解析器取值不一致）；`弱`：`X-Forwarded-Host`/`X-Original-URL`/`X-Rewrite-URL` —— 代理自己也会加这几个头，与客户端伪造字节相同（`X-Forwarded-For`/`X-Forwarded-Proto` 不报） | High |
| **request_smuggling** | 双重 `Transfer-Encoding` 头、`Content-Length: 0` 走私、`\r\n0\r\n` chunked 终止混淆 | High |
| **open_redirect** | `javascript:`/`data:text/html`/`data:text/plain` 伪协议跳转（要求 scheme 后跟内容）；`弱`：`//evil.com` 协议相对 URL —— 源码注释与文档里的 CDN 链接同形 | Medium |
| **cors** | `Access-Control-Allow-Origin: null`、`Access-Control-Allow-Origin: *` 与 `Access-Control-Allow-Credentials: true` **同现**；`弱`：请求侧 `Origin: null`（沙箱 iframe、`data:` URL、本地文件的源就是 `null`，要服务端用 `ACAO: null` 回显才成立）。两者单独出现是公开 API 与静态资源的常态，不报 | Medium |
| **websocket** | `Origin: null` 与 WebSocket 升级（`Upgrade: websocket`）同现（CSWSH）、`ws://` 指向环回 / 私网 / 链路本地地址（含云元数据端点 `169.254.169.254`） | High |
| **dns_rebinding** | Host 头为 `127.x`/`10.x`/`192.168.x`/`172.16-31.x` 内网 IP、`localhost`、`[::1]`、`0.0.0.0`。**整个检测器只有弱档**：一律上报 `Low`，见「已知上限」 | Low |
| **log4shell** | `${lower:j}`/`${upper:J}` 单字符大小写折叠、`${::-j}` 前缀折叠、`${env:…}ndi:` 等 lookup 展开后才拼出 JNDI（载荷不含 `jndi` 字面量）、`${${lower:…}}` 嵌套展开、`%24%7Blower%3Aj%7Dndi` URL 编码绕过 | Critical |
| **hpp** | `&` 与 `;` 分隔符混用（`?a=1&b=2;c=3`，两层解析器得出不同的参数个数）；`弱`：同名参数重复（`?id=1&id=2`）—— 与正常多值参数 `?tag=rust&tag=web` 字节完全相同；`;jsessionid=` 矩阵参数属路径分隔符，被排除 | Medium |

### 数据与序列化攻击（7 个检测器）

| 检测器 | 覆盖模式 | 严重度 |
|--------|---------|--------|
| **deserialization** | PHP `O:数字:`/`C:数字:` 序列化对象、`a:数字:{` 数组、`unserialize()` 调用、魔术方法**调用形态**（`__wakeup(`/`__destruct(`/`__construct(`/`__toString(`/`__get(`/`__set(`/`__call(`）；`弱`：裸魔术方法名（文档里讨论它们时同样命中） | Critical |
| **csv_injection** | 分隔符 `,`/`;`/`\t` 之后紧跟非空白的 `=`（TSV/CSV 第二个单元格里的公式）、行首 `DDE`、行首 `cmd\|` 命令管道、行首 `@SUM(` 函数；`弱`：行首 `=`/`+`/`-` 且其后既非空白也非同族符号（`- item` 列表项、`---` 分隔线、`++i`、`= 5` 均不命中）。`@` 已整体移出粗粒度层（`@media`/`@import` 在样式表里遍地都是），只保留 `@SUM(`。制表符与回车是**分隔符**，不是公式起始 | Medium |
| **mail_header** | 相邻两个 `From:` 头、行首 `MIME-Version:`（HTTP 的字段表里没有这个名字）；`弱`：行首 `Cc:`/`Bcc:` —— 与转发邮件、客服系统摄入的来信原文逐字节同形。`Content-Type: multipart` 与 `boundary=` **已删除**（`Content-Type: multipart/form-data` 是每个文件上传 POST 的标准头）。上限即 Medium（15 分），**不能单独越过拒绝线** | Medium |
| **jwt_attack** | `alg: none` 空算法绕过、`kid` 路径遍历注入、空签名段、空 payload 段 | High |
| **prototype_pollution** | `__proto__` 作键或被赋值（`"__proto__":`、`[__proto__]`、`__proto__ = x`）、`constructor.prototype`/`constructor[`、`__defineGetter__`/`__defineSetter__`/`__lookupGetter__`/`__lookupSetter__`、`hasOwnProperty[`；`弱`：裸 `__proto__`（`obj.__proto__` 读原型是语言本身的写法） | High |
| **formula_injection** | `=cmd\|' /C calc'!A0` 命令管道、`HYPERLINK()`/`IMPORTXML()`/`IMPORTDATA()`/`WEBSERVICE()`/`RTD()`/`EXEC()` 等外带数据函数、`=rundll32\|…!A0` 任意二进制 + DDE 单元格引用、`DDE(` 载荷、legacy `@SUM(` 前缀公式。只报能执行命令或外带数据的载荷（High），纯算术公式 `=SUM(A1:A5)` 归粗粒度层 **csv_injection**（Medium） | High |
| **redos** | 量词套量词 `(a+)+`/`(a*)*`/`(.+)+`、量词套有界重复 `(a+){2,}`、无界重复套量词 `(a{2,})*`、重叠分支 `(.\|x)+`/`(\d\|\w)*`、空分支 `(x\|)*`、同前缀分支 `(a\|ab)*`。防御方视角：把用户输入当正则编译前先扫一遍 | Medium |

### 文件与敏感数据（3 个检测器）

| 检测器 | 覆盖模式 | 严重度 |
|--------|---------|--------|
| **path_traversal** | **多级**跨越 `(?:\.\./){2,}`/`(?:\.\.\\){2,}`、`%2e%2e`/`..%2f`/`..%5c` URL 编码绕过、`php://filter`/`php://input`/`phar://`/`zip://`/`data://`/`expect://`/`glob://` 协议包装器、`%00` 空字节截断；`弱`：单级 `../`/`..\`（每份源码里的相对路径同形） | Critical |
| **upload** | `<?php`/`<?=` PHP 标签、`<%@`/`<%=` ASP 标签、`eval($_`/`system($_`/`exec($_`/`passthru($_` 后门模式、`$_GET`/`$_POST`/`$_REQUEST`/`$_SERVER` 超全局变量、`base64_decode()` 编码绕过 | Critical |
| **data_leak** | 16 位信用卡 PAN（Visa/MasterCard/AmEx/Discover/JCB/Diners）、AWS Access Key `AKIA...`、PEM 私钥头 `-----BEGIN`、OpenAI/LLM API Key `sk-...`、数据库连接串 `mongodb://`/`mysql://`/`postgresql://`/`redis://`（**必须带 `@` userinfo**：`mysql://root:secret@db` 报，`redis://shared-memory`、`postgres://localhost:5432/app` 这类是配置常态，**不报**）、`jdbc:`（无此约束）、JWT Token | Critical |

---

## 已知上限

以下几处是**已知且有意保留**的边界，不是待修的缺陷。改动前请先读依据 —— 每一条都出自实测，且都有人试过收紧后撞上同一堵墙。

### `dns_rebinding` 只上报，不拦截

它的判据是「`Host:` 头里出现内网地址」，而同一个形状也正是 k8s 里每个 pod 间调用（`Host: 10.244.1.5:8080`）、每次本地开发（`Host: localhost:8000`）、每个 Docker 容器网络请求（`172.18.0.2`）。真正的 rebinding 看的是「公网域名 + 解析结果指向内网」，而浏览器发出的 `Host` 恰恰是那个公网域名 —— **单条字符串里看不到解析历史**，本检测器测的形态与攻击形态并不重合，收紧成什么样都还是「内网地址出现」。因此整个检测器只有弱档，一律 `Low`；无论叠加多少条，它自己都不会越过拒绝线。防护在解析**之后**比对结果 IP，不在字符串层。

### 这个库扫不动自己的源码、测试和文档

签名扫描器的天花板：实测本仓库 298 个文件里有 78 个越过拒绝线，而它们**按构造**全都含有攻击串 —— 测试载荷、检测器源码里的正则字面量自身，以及列出这些模式的 README 与 OWASP 表格。一份 README 不会因为写了 `(a+)+` 而变成缺陷。要扫自己的产物，得先把这些语料排除，或者换一个判据。

### `upload` 一律把 `<%@` / `<?php` 报为 Critical

该检测器的契约是「**这个 blob 是服务端可执行代码**」—— 出现即成立，因此不设强弱分层。JSP 页面与 JSP webshell 的前导字节逐字节相同（`<%@ page language="java" … %>` 与 `<%@ page import="java.io.*" %>` 是同一形态），把 `<%@`/`<%=` 降档等于让 webshell 落到拒绝线以下 —— 那是换个方式删检测。代价是扫描**正在对外提供的**页面（而不是上传的文件）时也会命中，那属于输入域不符 —— 命中消息 `Malicious file upload detected` 已点明域。

### `path_traversal` 把 `(?:\.\./){2,}` 报为 Critical

monorepo 里的深层相对路径（`from '../../../shared/domain'`）会命中。没有进一步收紧，因为唯一能把它与攻击分开的约束是目标文件名列表（`../etc/passwd` 那一类），而那只覆盖系统文件 —— 攻方换一个 LFI 目标就绕过去了。

---

## 生命周期

<img src="./docs/diagrams/lifecycle.svg" alt="security-rust 三条生命周期：扫描、会话、限流" width="900">

三条生命周期互相独立，唯一的交汇点是调用方的请求处理函数：

| 生命周期 | 起点 | 终点 | 状态存放 |
|---------|------|------|---------|
| **扫描** | `Scanner::scan(&str)` | `Vec<DetectionResult>` → `score::assess` → `RiskAssessment` | 无状态，每次调用独立 |
| **会话** | `SessionGuard::bind()` 写 `SessionRecord` | 每请求 `verify()` → `SessionVerdict` ⇒ `Allow` / `Challenge` / `Block` | `SessionStore`（内置 `MemoryStore`） |
| **限流** | `Throttle::check_any(&[keys])` | `Allow{remaining}` / `Banned{until}` / `Unavailable` | `ThrottleStore`（内置 `MemoryThrottleStore`） |

两条容易踩的边界：

- **`remaining == 0` 表示本请求应被拒绝** —— 额度已耗尽，不是「还能再试一次」。要写进 `X-RateLimit-*` 时别写反。
- **存储故障的处置两边相反**：`SessionGuard` fail-closed（`StoreUnavailable` ⇒ `Block`，绝不放行，否则攻击者诱导故障就能换掉一整类判定）；`Throttle` fail-open（`Unavailable` 交调用方，后端抖动时把全体用户挡在门外是自我 DoS，主闸门 `SessionGuard` 仍在拦）。这是写死的设计，不是漏写的兜底。

---

## 使用说明

零配置即可使用：

```rust
use security_rust::Scanner;

let scanner = Scanner::default();

// 强信号：形态本身只可能来自攻击 ⇒ 按检测器声明的严重度上报
let results = scanner.scan("<img src=x onerror=alert(1)>");
// [CRITICAL] XSS cross-site scripting detected — offset: 11, pattern: onerror=

// 弱信号：token 出现而已 ⇒ 固定 Low，不单独越过拒绝线（见「两档判定」）
let weak = scanner.scan("<script src=\"/app.js\"></script>");
// [LOW] XSS tag present (weak signal) — offset: 0, pattern: <script>
```

风险评分把命中列表汇成一个等级，避免多条低危信号被静默忽略：

```rust
let assessment = scanner.assess("=cmd|' /C calc'!A0 `cat /etc/passwd` ../../../etc/passwd");
// assessment.level   >= RiskLevel::High
// assessment.results >= 3
// assessment.score   — 原始加权分
```

完整 API 参考（安装、选择性扫描、自定义配置、风险评分、严重度展示、会话安全、限流与封禁、性能）见 [API 参考](./docs/API.md)。

### 会话安全（`session`）

```rust
use security_rust::session::{Decision, MemoryStore, RequestContext, SessionConfig, SessionGuard};

let guard = SessionGuard::new(MemoryStore::new(), SessionConfig::default());

let login = RequestContext {
    token: "tok-abc",
    subject: "u-1",
    fingerprint: "ip=1.2.3.4|ua=curl",   // 客户端指纹，登录时绑定
    location: Some("CN-BJ"),
    coords: Some((39.9042, 116.4074)),
    signature: None,                      // MAC 由调用方签发
    at: None,
};

// 登录：建会话 + 绑指纹 + 记位置；异地只影响 verdict，不阻断登录
guard.bind(&login, 1_700_000_000).unwrap();

// 每请求校验：同一个 token，换一个指纹 ⇒ 客户端劫持
let verdict = guard.verify(&RequestContext { fingerprint: "ip=5.6.7.8|ua=curl", ..login }, 1_700_000_010);

match verdict.decision {
    Decision::Allow => { /* 放行 */ }
    Decision::Challenge => { /* 放行但要求二次验证：异地、时钟偏离、签名意外 */ }
    Decision::Block => { /* 拒绝 */ }
}
```

### 限流与封禁（`throttle`）

```rust
use security_rust::throttle::{MemoryThrottleStore, Throttle, ThrottleConfig, ThrottleDecision};

let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());
let key = "acct:u-1"; // key 由调用方构造并规范化，不要直接拿原始输入当 key
let now = 1_700_000_000;

// 真实请求有两个维度：IP 与账户。check_any 一次问完，按严格度合并
match throttle.check_any(&["ip:1.2.3.4", key], now) {
    // remaining 可写进 X-RateLimit-*；**remaining == 0 表示本请求应被拒绝**
    ThrottleDecision::Allow { remaining } => { /* 剩余额度 remaining */ }
    // now >= until 即视为已解封
    ThrottleDecision::Banned { until } => { /* 封禁中，until 解封 */ }
    // 后端故障：本模块不替调用方做决定（建议放行 + 告警）
    ThrottleDecision::Unavailable => { /* 限流后端不可用 */ }
}

// 认证失败记一笔：达到 threshold 即封禁。返回 ThrottleOutcome（两态），
// 存储故障走 Err —— 不必为一个永不执行的 Unavailable 臂写死代码
let _ = throttle.record_failure(key, now);
```

---

## 开发

```bash
# 构建
cargo build --release

# 测试（580 个：431 单元 + 148 集成 + 1 文档测试）
cargo test

# 端到端流水线示例（扫描 → 限流 → 会话 → 处置）
cargo run --example waf

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
