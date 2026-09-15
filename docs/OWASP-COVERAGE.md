<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# OWASP Top 10 (2021) 覆盖矩阵与能力边界

本文回答一个问题：**面对某一类 OWASP 风险，这个库能帮上多少、帮不上什么。**

`security-rust` 是**输入侧检测库**，不是完整防护方案。它接收字符串、返回结构化检测结果（`Scanner`），另外提供三个有状态模块（`session` / `throttle` / `score`）。判断「命中即拦截」还是「命中只记日志」由调用方决定。

阅读约定：

| 标记 | 含义 |
|------|------|
| ✅ | 有对应检测器或模块，点名见「覆盖方式」 |
| 🟡 | 部分覆盖：只解决了这一类风险的一半，另一半必须由别的手段补齐 |
| ❌ | 不在范围内：本库对该类风险不产生任何信号 |

---

## 1. 主矩阵

| OWASP 条目 | 本库覆盖 | 覆盖方式 | 缺口 |
|------------|----------|----------|------|
| A01:2021 Broken Access Control | 🟡 | `path_traversal`、`open_redirect`、`hpp`；`session` 的 `revoke` / `revoke_all` | 没有「谁能访问什么」的判定：无对象级授权、无权限矩阵、无多租户隔离、无 CSRF 校验 |
| A02:2021 Cryptographic Failures | ❌ | 无（唯一相邻信号：`data_leak`） | 不做任何密码学决策：不选算法、不校验 TLS、不管密钥与口令哈希 |
| A03:2021 Injection | ✅ | `xss`、`sql_injection`、`command_injection`、`nosql_injection`、`ldap_injection`、`xpath_injection`、`jndi_injection`、`ssi_injection`、`graphql_injection`、`ssti`、`format_string`、`log4shell`、`header_injection`、`mail_header`、`csv_injection`、`formula_injection` | 字面量正则：不递归解码、无语法上下文、看不见二阶注入；检测不等于防护 |
| A04:2021 Insecure Design | ❌ | 无（相邻：`redos`、`throttle`） | 设计缺陷没有载荷特征，只能靠威胁建模与业务规则约束 |
| A05:2021 Security Misconfiguration | 🟡 | `cors`、`header_injection`、`host_header`、`request_smuggling`、`websocket`、`xxe`、`upload` | 不读配置、不扫目录、不检查默认口令/调试开关/安全响应头/TLS —— 看到的是载荷，不是上线配置 |
| A06:2021 Vulnerable and Outdated Components | ❌ | 无 | 不解析依赖清单、不识别版本、不查 CVE。需 `cargo-audit` / Dependabot / SBOM |
| A07:2021 Identification and Authentication Failures | 🟡 | `session::SessionGuard`、`throttle::Throttle`、`jwt_attack` | 不做认证本身：不校验口令、不算 MAC、不签发 token、不做 MFA |
| A08:2021 Software and Data Integrity Failures | 🟡 | `deserialization`、`prototype_pollution`、`jwt_attack`、`csv_injection`、`formula_injection` | 不验证签名与制品、无反序列化白名单；Java/Python/.NET/Ruby 反序列化无专规则 |
| A09:2021 Security Logging and Monitoring Failures | 🟡 | `score::assess`（`RiskLevel` + 数值 score）、`DetectionResult` 结构化字段、`SessionGuard` 的 threats 列表 | 不写日志、不落盘、不发告警、不做事件关联；也不判断哪个事件值得告警 |
| A10:2021 Server-Side Request Forgery (SSRF) | ✅ | `ssrf`、`dns_rebinding` | 只匹配字面量主机/IP：进制变形、IPv6 映射、DNS rebinding 的 TOCTOU 都不覆盖 |

### 逐条说明

#### A01 Broken Access Control —— 🟡 只有「路径与跳转」这一层

- `path_traversal` 匹配 `../`、`..\`、`..%2f`、`%2e%2e`、`%00` 空字节，以及 `php://filter`、`php://input`、`data://`、`expect://`、`phar://`、`zip://`、`glob://` 等流包装器。
- `open_redirect` 匹配 `//evil.com` 形式的协议相对跳转，以及 `javascript:`、`data:text/html`、`data:text/plain`。
- `hpp` 检出同名参数重复（`a=1&a=2`）—— 这类污染可以让服务端取到与授权判断所用的**不同**那份参数值。
- `session::SessionGuard::revoke` / `revoke_all` 让「登出」「改密码后踢下线」具备可执行的失效面。

**缺口**：本库不知道「这个用户能不能碰这个对象」。IDOR、越权查询、多租户数据串号、CSRF、目录级授权，一条都测不了 —— 它们取决于服务端持有的会话与权限数据，与输入字符串无关。这些要靠对象级授权校验（每次取数据都用「当前主体 + 目标 ID」查一遍）、服务端会话对象、CSRF token 机制。`path_traversal` 命中的是路径载荷，不是「这个路径该不该被访问」。

#### A02 Cryptographic Failures —— ❌ 完全不做密码学

本库不含任何加密、解密、哈希、随机数或密钥管理代码，也不检查 TLS 配置、证书、算法强度、口令哈希是否加盐。

唯一相邻的是 `data_leak`：当输入里出现明文私钥（RSA/DSA/EC/PGP）、`AKIA` 云凭证、`sk-` API key、`mongodb://` / `mysql://` / `postgres://` / `redis://` / `jdbc:` 连接串，或通过 Luhn 校验的银行卡号时，给出 `Severity::Critical`。注意它是**「敏感数据出现在了输入里」**，与「密码学实现失败」不是同一件事：能测出泄露，不等于测不出弱算法。

该用：OWASP Cryptographic Storage / Secrets Management / Key Management Cheat Sheet，配合 TLS 终止层配置检查与 `argon2` / `rustls` 这类专门实现。

#### A03 Injection —— ✅ 覆盖最厚的一条，但仍不是防护

16 个检测器分工如下（括号内为主特征）：

| 检测器 | 主要特征 |
|--------|----------|
| `xss` | `<script` / `<svg` / `<iframe` / `<embed` / `<object` / `<link` / `<meta`、`on*=` 事件处理器全表、`javascript:` / `vbscript:` / `data:text/html`、`eval(` / `fromCharCode(` / `document.cookie` / `document.write(` |
| `sql_injection` | `UNION [ALL] SELECT`、`SELECT ... FROM`、时间盲注（`sleep(` / `benchmark(` / `pg_sleep(` / `WAITFOR DELAY`）、`information_schema`、`LOAD_FILE(` / `INTO OUTFILE` / `DROP TABLE`、注释符截断（`--`/`#`/`/*`）与 `' OR '1'='1` |
| `command_injection` | 反引号、`$(...)`、`\| cmd`、`\|\| cmd`、`&& cmd`、`/dev/tcp`、`system(` / `exec(` / `shell_exec(` / `passthru(` / `popen(` / `pcntl_exec(`、`cmd.exe` / `powershell` |
| `nosql_injection` | `{"$ne":` / `$gt` / `$regex` / `$where` / `$or` / `$nin` 等 MongoDB 操作符 |
| `ldap_injection` | `(&` / `(\|` / `(!(`、`*(cn=`、`(objectClass=`、`(uid=` |
| `xpath_injection` | `' or '1'='1`、`' and '1'='2`、`' or true(`、`' ] \| ` |
| `jndi_injection` | `${jndi:` 及 `${lower:j}` / `${upper:j}` / `${::-j}` 等绕过写法、`${env:` / `${sys:` / `${java:` |
| `log4shell` | Log4j lookup 混淆：`${lower:x}`、`${::-x}` 嵌套、URL 编码 `%24%7b`，覆盖 `jndi/lower/upper/env/sys/date/java/base64/...` |
| `ssi_injection` | `<!--#exec cmd=` / `<!--#include file=` / `<!--#echo var=` / `#fsize` / `#flastmod` / `#config` / `#printenv` |
| `graphql_injection` | `__schema` / `__type {` / `__typename` 内省，以及五层以上嵌套查询 |
| `ssti` | `{{ }}` / `${ }` / `{% %}`、`<%=` / `<%@`、`#set(`、Python 逃逸链 `__mro__` / `__subclasses__` / `__globals__` / `__builtins__` / `__class__` |
| `format_string` | `%n` 写内存（含位数与长度修饰符组合）、`%999999d`、连续 `%x` / `%s` 泄露栈 |
| `header_injection` | CRLF 后接 `Set-Cookie` / `Location` / `Content-Length` / `Transfer-Encoding` / `Refresh` / `Status` / `WWW-Authenticate`，或 `%0d` 与 `%0a` 同时出现 |
| `mail_header` | `Bcc:` / `Cc:` / `MIME-Version:` / `boundary=`、`Content-Type: ...multipart`、重复 `From:` |
| `csv_injection` | 行首 `= + - @ \t \r`、`DDE`、`cmd\|`、`@SUM(` |
| `formula_injection` | 行首或分隔符后的公式起始符 + `cmd\|` / `HYPERLINK` / `IMPORTXML` / `IMPORTDATA` / `IMPORTRANGE` / `IMPORTFEED` / `WEBSERVICE` / `FILTERXML` / `RTD` / `EXEC`、`DDE(`、DDE 外部引用（`'file'!A1`） |

**缺口**（这一节比上面那张表重要）：

1. **字面量匹配，不递归解码。** 匹配发生在原始字符串上。`%3Cscript%3E`、HTML 实体、Unicode 转义、双写（`<scr<script>ipt>`）、SQL 中的 `/**/` 拆词，都不保证命中。
2. **没有语法上下文。** 同一条输入落在 HTML 文本、JS 字符串、SQL 字面量还是 shell 参数里，风险完全不同；本库只看字符串，不看位置。因此无法判断「这个反引号是数据还是命令」。
3. **看不见二阶注入。** 存库时干净、取出拼接时才成形的注入，需要数据流分析；单次输入的扫描器在原理上就看不到。
4. **检测不等于防护。** 命中只是「疑似」，可以被裁掉；未命中不代表安全。防注入的根本手段在数据流向的两端 —— 参数化查询（Query Parameterization）、输出编码与上下文转义、不拼接 shell 命令。本库的正则只是这条链上的补充信号，不能替代其中任何一环。

#### A04 Insecure Design —— ❌ 设计缺陷不是字符串

业务逻辑漏洞（优惠券叠加、越权退款、流程跳步、竞态扣减）没有可匹配的载荷特征。

两处相邻能力：`redos` 识别灾难性回溯的正则**写法**（`(a+)+`、`(\d|\w)+`、嵌套量词、重复前缀分支），属于算法复杂度缺陷；`throttle` 提供「按 key 的失败配额 + 封禁」这一个反自动化原语。二者都不是设计评审。

该用：威胁建模、abuse case 评审、业务规则约束（额度、状态机、幂等键）、并发控制。

#### A05 Security Misconfiguration —— 🟡 看见的是载荷，不是配置

- `cors`：`Origin: null`、`Access-Control-Allow-Origin: *`、`Access-Control-Allow-Credentials: true`。
- `header_injection`：响应头注入（CRLF 拆出 `Location` / `Set-Cookie` 等）。
- `host_header`：CRLF 后伪造 `Host`、`X-Forwarded-*`、`X-Original-URL`、`X-Rewrite-URL` —— 这正是密码重置链接投毒、缓存投毒依赖的头部。
- `request_smuggling`：重复 `Transfer-Encoding`、`Transfer-Encoding: chunked`。
- `websocket`：`Upgrade: websocket`、`Sec-WebSocket-Key:`、`Origin: null` 与 `Upgrade` 同现、`ws://`。
- `xxe`：`<!DOCTYPE`、`<!ENTITY`、`SYSTEM "..."`、`PUBLIC "..."`（XML 解析器被允许展开外部实体，本质是解析器配置问题）。
- `upload`：webshell 特征 —— `<?php` / `<?=` / `<% @` / `<script language="php">`、`eval($_` / `system($_` / `passthru($_` 等、`$_GET[` / `$_POST[` / `$_REQUEST[` / `$_SERVER[`、`base64_decode(`。

**缺口**：本库不读你的配置文件，不扫端口和目录，不检查默认口令、调试开关、错误页堆栈泄露、`X-Content-Type-Options` / HSTS / CSP 等响应头是否下发、TLS 版本与套件是否合规。上列检测器看到的是**攻击载荷**，或（当调用方把报文/响应文本喂进来时）**报文里出现的危险头**，不是对上线配置的审计。

该用：配置基线扫描（kubectl/Trivy/云厂商合规检查）、安全响应头检查、镜像与发布流程配置审计。

#### A06 Vulnerable and Outdated Components —— ❌ 不认识组件

不解析 `Cargo.lock` / `package-lock.json` / SBOM，不比较版本，不查 CVE 库，也不识别 `Server:` / `X-Powered-By` 这类版本横幅。

本库自身的依赖只有 `regex`（见 `Cargo.toml`），这只缩小了**本库**的供应链面，替不了你的应用治理组件风险。

该用：`cargo-audit`、Dependabot / Renovate、SBOM 生成与比对、OWASP Dependency-Check。

#### A07 Identification and Authentication Failures —— 🟡 管会话，不管认证

- `session::SessionGuard` 检查：token 未知 / 已过期 / 已吊销、指纹不匹配（会话固定/劫持）、签名不匹配或缺失（常量时间比较）、请求时间偏移（重放）、位置变化、不可能旅行、store 不可用（fail-closed → `Block`）。返回 `SessionVerdict { decision: Allow | Challenge | Block, severity, threats }`，并支持 `revoke` / `revoke_all` / `rotate`。
- `throttle::Throttle` 按 key 统计窗口内失败次数，达到阈值即封禁 —— 面向暴力破解与撞库。store 故障时返回 `Unavailable` 而**不是** `Banned`（限流是纵深防御，不是主闸门，不让后端抖动变成自我 DoS）。
- `jwt_attack` 匹配 `"alg":"none"`、`"kid"` 指向 `../` 或 `/dev/null`、`eyJ...eyJ...` 的无签名/截断 JWT 结构。

**缺口**：不做认证本身。不校验口令、不做 MFA、不查泄露口令库、不签发 token、**不计算 MAC** —— `RequestContext.signature` 必须是调用方算好的值传进来。`session` 判的是「这个会话是否被劫持或篡改」，不判「这个人凭据是否正确」；`throttle` 判的是「这个 key 试太多次了」，同样不等于身份可信。

该用：Authentication / Session Management / Credential Stuffing Prevention / JSON Web Token Cheat Sheet，加上真正的认证服务与 MFA。

#### A08 Software and Data Integrity Failures —— 🟡 只覆盖「不安全反序列化」这一子类

- `deserialization`：PHP 序列化特征 `O:len:"..."` / `C:len:"..."`、`unserialize(`、魔术方法 `__wakeup` / `__destruct` / `__construct` / `__toString` / `__call` / `__get` / `__set`、数组 `a:N:{`。
- `prototype_pollution`：`__proto__`、`constructor.prototype`、`constructor[`、`__defineGetter__` / `__defineSetter__` / `__lookupGetter__` / `__lookupSetter__`、`hasOwnProperty[`。
- `jwt_attack`：签名剥离 / `alg:none` —— 完整性校验被绕过的结构特征。
- `csv_injection` / `formula_injection`：数据被**下游**表格软件当作公式或 DDE 命令执行，是「不可信数据未经校验直接进入下一环节」的典型。

**缺口**：不验证任何签名或制品 —— 没有 MAC 校验、没有反序列化类型白名单、没有 CI/CD 与依赖完整性校验、不校验数据来源。反序列化规则以 PHP 特征与 JS 原型链为主：Java gadget 链（ysoserial 系）、Python `pickle`、.NET `BinaryFormatter`、Ruby `Marshal` 都没有专门规则（其中一部分可能被 `command_injection` / `format_string` 顺带命中，但**不能依赖**）。

该用：Deserialization Cheat Sheet（只用白名单类型 + 签名校验，禁止原生反序列化不可信数据）、制品签名与来源校验。

#### A09 Security Logging and Monitoring Failures —— 🟡 产出信号，不产出日志

- `score::assess(&results)` 把单次输入的多条命中聚合成 `RiskAssessment { level: RiskLevel, score, results }`，`RiskLevel` 为 `None | Low | Medium | High | Critical`，多条低危叠加可升级 —— 这是「风险累积」而非「有/无命中」。
- `DetectionResult` 带 `attack_type` / `category` / `severity` / `matched_pattern` / `offset` / `message`，结构化，可直接进日志或告警管道。
- `SessionGuard` 的 threats **逐项收集、不提前退出**，为的是日志与取证完整。

**缺口**：本库不写日志、不落盘、不发告警、不做时间线关联；只有内存 store（`MemoryStore` / `MemoryThrottleStore`），进程结束即丢；也不判断「哪个事件值得告警」（无阈值、无去重、无白名单）。

注意 `Severity` 是 4 档（`Critical` / `High` / `Medium` / `Low`）且**没有实现 `Ord`** —— 它的声明顺序是递减的，派生 `Ord` 会得到恰好相反的比较结果。按严重度排序必须走显式 rank（`session` 模块内的 `severity_rank` 即为此而写）；`RiskLevel` 有 `Ord`，但枚举顺序与 `Severity` 相反，两者不要混用 `max()`。

#### A10 Server-Side Request Forgery —— ✅ 有专门检测器，但别当成出站策略

- `ssrf`：云元数据地址 `169.254.169.254`、RFC1918 三段（`10.` / `172.16-31.` / `192.168.`）、`127.0.0.0/8`、`[::1]`、`0.0.0.0`，以及危险协议 `gopher://` / `dict://` / `file:///` / `ftp://user@host`。
- `dns_rebinding`：`Host:` 头指向内网段、`localhost`、`[::1]`、`0.0.0.0` —— DNS rebinding 的利用前提是服务端按字面主机名做了「看起来安全」的判断。

**缺口**：只匹配字面量。进制变形（`2130706433`、`0177.0.0.1`、`0x7f.1`）、IPv6 映射（`::ffff:127.0.0.1`）、URL 用户名混淆（`http://expected.com@internal/`）、302 跳转、以及「解析后指向内网的自有域名」都不保证命中。真正的 rebinding 防护是解析**之后**再比对结果 IP，本库在字符串层面做不了这件事（检查时的解析与请求时的解析可以不同，这本身就是 TOCTOU）。

该用：服务端出站白名单、元数据端点隔离（IMDSv2 / 网络策略）、解析后 IP 校验、禁止跟随重定向。

---

## 2. 本库不做的事

这一节请先于功能列表阅读。以下是**明确不做**的，不是「暂未实现」，而是定位使然：

| 不做 | 说明 |
|------|------|
| **不做输出编码 / 参数化查询** | 防注入的根本手段在数据流向的两端 —— 出口的上下文编码与参数化查询，入口的正则检测只是补充。本库没有数据库驱动、没有模板引擎、没有 HTTP 客户端，物理上也做不了 |
| **不解析 HTTP** | 不绑定任何 Web 框架，不解析请求行/头部/正文边界，不做 chunked 解码、不做 multipart 拆解、不做 URL 解码。喂进来的是字符串，边界由调用方定义 |
| **不做认证与授权** | `session` 只管会话的完整性与可疑性（token 状态、指纹、签名、时间、位置），不判断「这个用户能不能做这件事」。认证成功与否由调用方定 |
| **不计算签名 / 不签发 token** | 零依赖的代价：本库没有 HMAC 实现。`RequestContext.signature` 必须是调用方算好的值；token 的生成、格式、有效期声明也由调用方提供。`jwt_attack` 只做结构特征匹配，**不验证 JWT 签名** |
| **不内置 GeoIP** | 位置由调用方用已有的 geo 库从 IP 解析后传入（`RequestContext.location` / `coords`）。本库只在坐标上做不可能旅行计算（会校验 NaN 与越界） |
| **不做持久化** | 只提供内存实现的 store（`MemoryStore` / `MemoryThrottleStore`）。要实现跨进程、跨节点、可重启的会话与限流，需自行实现 `SessionStore` / `ThrottleStore` trait |
| **正则覆盖不到的类别** | 业务逻辑缺陷、竞态条件、供应链、配置错误、设计缺陷 —— 这些没有可匹配的字符串特征，只能靠评审、约束与流程解决 |

另需注意几处**设计上的误报面**（属取舍而非缺陷，调用方需自行判读）：

- `websocket` 会把正常握手（`Upgrade: websocket` 与 `Sec-WebSocket-Key` 是握手必需头）判为 `High`。
- `csv_injection` 认行首 `= + - @ \t \r`，正常文本里以 `-` 或 `=` 开头的行会命中（属粗粒度层，靠 `Scanner::assess` 的累积评分而非单条命中下判断）。
- `cors` 的 `Access-Control-Allow-Origin: *`、`Origin: null` 在合法场景（公开静态资源、沙箱 iframe、`file://` 页面）也会出现。
- `ssti` 认 `${` / `{{ }}` 这类模板语法，前端模板源码或 i18n 占位符可能命中。

---

## 3. 横向补充：不在 OWASP Top 10 里的能力

下列能力在 Top 10 (2021) 中没有独立条目，但对应用户更具体的 OWASP 文档。表中「OWASP 文档」一列只列已核对存在的；未核对到专篇的，如实标注，不臆测编号。

| 能力 | 检测器 / 模块 | 更具体的 OWASP 文档 |
|------|----------------|----------------------|
| SSRF 与 DNS rebinding | `ssrf`、`dns_rebinding` | OWASP API Security Top 10 — API7:2023 Server Side Request Forgery；Server Side Request Forgery Prevention Cheat Sheet |
| WebSocket 握手劫持 | `websocket` | WebSocket Security Cheat Sheet |
| HTTP 请求走私（TE/CL 冲突） | `request_smuggling` | OWASP ASVS — V4.2 HTTP Message Structure Validation（编号取自 OWASP Cheat Sheet Series 的 ASVS 索引） |
| Host 头攻击 / 缓存与密码重置投毒 | `host_header` | 未核对到专篇（主题上属 API8:2023 Security Misconfiguration） |
| HTTP 参数污染 | `hpp` | 未核对到专篇 |
| 响应头注入 / CRLF | `header_injection` | 未核对到专篇（主题上属 ASVS V1.2 Injection Prevention） |
| Open redirect | `open_redirect` | Unvalidated Redirects and Forwards Cheat Sheet |
| CORS 错配 | `cors` | HTML5 Security Cheat Sheet |
| CSV / 公式注入（含 DDE） | `csv_injection`、`formula_injection` | OWASP CSV Injection 页面 |
| 邮件头注入 | `mail_header` | 未核对到专篇 |
| 正则拒绝服务（ReDoS） | `redos` | Denial of Service Cheat Sheet |
| 原型污染 | `prototype_pollution` | Prototype Pollution Prevention Cheat Sheet |
| JWT 结构攻击（alg:none / kid 穿越） | `jwt_attack` | JSON Web Token Cheat Sheet |
| 不可能旅行 / 异地登录 / 会话劫持 | `session` | OWASP ASVS — V7.5 Defenses Against Session Abuse（同上索引） |
| 限流封禁 / 撞库防护 | `throttle` | OWASP API Security Top 10 — API4:2023 Unrestricted Resource Consumption；Credential Stuffing Prevention Cheat Sheet |
| 凭证与敏感数据泄露检出 | `data_leak` | Secrets Management Cheat Sheet |
| 不安全文件上传（webshell 特征） | `upload` | File Upload Cheat Sheet |
| 服务端模板注入 / 表达式语言注入 | `ssti`、`format_string`、`log4shell` | Injection Prevention Cheat Sheet；OS Command Injection Defense Cheat Sheet（`format_string` 的 `%n` 内存写属 Injection 主题） |
| 图查询内省与深度滥用 | `graphql_injection` | GraphQL Cheat Sheet |
| LDAP / XPath 查询注入 | `ldap_injection`、`xpath_injection` | LDAP Injection Prevention Cheat Sheet；Injection Prevention Cheat Sheet |
| SSI 服务端包含注入 | `ssi_injection` | Injection Prevention Cheat Sheet |

**OWASP Top 10 之外、本库完全不做**：CSRF token 校验、点击劫持防护、反自动化挑战（CAPTCHA）、恶意文件静态扫描（病毒特征）、Bot 指纹识别、数据脱敏与掩码。

---

## 4. 附录：32 个检测器全清单

按 `Detector::name()` 字母序（与 `Scanner::default()` 的装配顺序无关）。`Severity` 为该检测器固定返回的等级，`AttackCategory` 为 `DetectionResult.category`。

| `name()` | 分类 | Severity | 本文出现位置 |
|----------|------|----------|--------------|
| `command_injection` | Injection | Critical | A03、补充表 |
| `cors` | Protocol | Medium | A05、补充表 |
| `csv_injection` | Data | Medium | A03、A08、补充表 |
| `data_leak` | File | Critical | A02、补充表 |
| `deserialization` | Data | Critical | A08 |
| `dns_rebinding` | Protocol | High | A10、补充表 |
| `format_string` | Injection | Medium | A03、补充表 |
| `formula_injection` | Data | High | A03、A08、补充表 |
| `graphql_injection` | Injection | Medium | A03、补充表 |
| `header_injection` | Protocol | High | A03、A05、补充表 |
| `host_header` | Protocol | High | A05、补充表 |
| `hpp` | Protocol | Medium | A01、补充表 |
| `jndi_injection` | Injection | Critical | A03 |
| `jwt_attack` | Data | High | A07、A08、补充表 |
| `ldap_injection` | Injection | High | A03、补充表 |
| `log4shell` | Protocol | Critical | A03、补充表 |
| `mail_header` | Data | Medium | A03、补充表 |
| `nosql_injection` | Injection | Critical | A03 |
| `open_redirect` | Protocol | Medium | A01、补充表 |
| `path_traversal` | File | Critical | A01 |
| `prototype_pollution` | Data | High | A08、补充表 |
| `redos` | Data | Medium | A04、补充表 |
| `request_smuggling` | Protocol | High | A05、补充表 |
| `sql_injection` | Injection | Critical | A03 |
| `ssi_injection` | Injection | High | A03、补充表 |
| `ssrf` | Protocol | Critical | A10、补充表 |
| `ssti` | Injection | Critical | A03、补充表 |
| `upload` | File | Critical | A05、补充表 |
| `websocket` | Protocol | High | A05、补充表 |
| `xpath_injection` | Injection | High | A03、补充表 |
| `xss` | Injection | Critical | A03 |
| `xxe` | Protocol | Critical | A05 |

分类计数：Injection 11、Protocol 11、Data 7、File 3，合计 32。

检测器只覆盖字符串输入。会话安全（`session`）与限流封禁（`throttle`）是**有状态、身份相关**的模块，不实现 `Detector` trait，也不在 `Scanner` 的装配范围内，需通过各自的显式 API 调用；风险评分由 `Scanner::assess` / `score::assess` 提供。
