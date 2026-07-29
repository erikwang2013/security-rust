<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# 代码审查报告 — security-rust

**日期**: 2026-07-29  
**审查范围**: 全部源码 (27 个检测器 + 核心框架 + 测试)  
**测试结果**: 46/46 全部通过  
**Clippy**: 零警告  
**Cargo fmt**: 已通过  
**Rust edition**: 2024

---

## 一、项目概况

security-rust 是一个纯 Rust 安全攻击检测库，覆盖 4 大类 27 种攻击向量：

| 分类 | 检测器 | 数量 |
|------|--------|------|
| 注入 (Injection) | XSS, SQL注入, 命令注入, NoSQL注入, LDAP注入, XPath注入, JNDI注入, SSI注入, GraphQL注入, SSTI | 10 |
| 协议 (Protocol) | SSRF, XXE, Header注入, Host Header, 请求走私, 开放重定向, CORS, WebSocket, DNS重绑定 | 9 |
| 数据 (Data) | 反序列化, CSV注入, 邮件头注入, JWT攻击, 原型污染 | 5 |
| 文件 (File) | 路径穿越, 恶意上传, 数据泄露 | 3 |

---

## 二、本轮修复的问题（2026-07-29 第二轮审查）

### 2.1 JNDI 注入检测器误报风险 — 已修复

**文件**: `src/injection/jndi_injection.rs`  
**问题**: 检测器包含 4 个裸协议模式 — `ldap://`、`rmi://`、`dns://`、`ldaps://`

这些模式匹配**任何**包含这些 URL scheme 的输入。例如，正常业务中出现的 `ldap://directory.company.com` 会被误报为 JNDI/Log4Shell 注入。

真正的 JNDI 注入攻击已被 `${jndi:...}` 及混淆变体模式完全覆盖。移除这 4 个裸协议模式不会影响检测能力，但消除了严重的误报来源。

```rust
// 移除前（第16-20行）
Regex::new(r"(?i)ldap://").unwrap(),
Regex::new(r"(?i)rmi://").unwrap(),
Regex::new(r"(?i)dns://").unwrap(),
Regex::new(r"(?i)ldaps://").unwrap(),

// 移除后 — 已删除
```

### 2.2 数据泄露检测器职责混淆 — 已修复

**文件**: `src/file/data_leak.rs`  
**问题**: `PATTERNS` 中包含 JWT 令牌匹配模式 `eyJ...`

JWT 令牌检测属于 `JwtAttackDetector`（`src/data/jwt_attack.rs`）的职责范围。放在 `data_leak` 中造成：
- 职责重叠：同一个 JWT 可同时被归类为 "data_leak" 和 "jwt_attack"
- 语义错误：JWT 令牌本身不一定泄露，它只是一种数据格式

```rust
// 移除前（第13行）
Regex::new(r"(?i)eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").unwrap(),

// 移除后 — 已删除
```

### 2.3 请求走私检测器合法 HTTP 模式 — 已修复

**文件**: `src/protocol/request_smuggling.rs`  
**问题**: 包含 2 个合法 HTTP/1.1 协议元素的模式

- `Content-Length:[\s]*0` — Content-Length: 0 是无请求体的正常 HTTP 请求
- `\r\n0\r\n` — 这是 chunked transfer encoding 的标准终止序列

这些模式会在正常的 HTTP 流量上产生误报。保留的 `Transfer-Encoding` 重复头模式足以检测真正的请求走私攻击。

```rust
// 移除前（第12-13行）
Regex::new(r"(?i)Content-Length:[\s]*0").unwrap(),
Regex::new(r"(?i)\r\n0\r\n").unwrap(),

// 移除后 — 已删除
```

---

## 三、前一轮已修复的问题

### 3.1 Clippy 警告修复 (4处)

| # | 文件 | 问题 | 修复 |
|---|------|------|------|
| 1 | `src/file/data_leak.rs` | `sum % 10 == 0` 手写取模 | 改用 `sum.is_multiple_of(10)` |
| 2 | `src/file/data_leak.rs` | 嵌套 if 可合并 | 合并为 `if let Some(m) = ... && luhn_valid(...)` |
| 3 | `src/scanner.rs` | `Scanner::default()` 应实现标准 trait | 改为 `impl Default for Scanner` |
| 4 | `src/scanner.rs` | `scan_with` 中嵌套 if 可合并 | 合并为 `if names.contains(...) && let Some(...) = ...` |

### 3.2 死代码清理

| # | 文件 | 问题 | 修复 |
|---|------|------|------|
| 5 | `src/result.rs` | `AttackCategory::Http` 变体定义但全项目零引用 | 删除 `Http` 变体 |
| 6 | `src/scanner.rs` | `ScannerBuilder` 含 8 个保留字段 + 8 个方法且 `build()` 忽略 | 删除所有未使用字段及方法 |

---

## 四、已验证正确的设计

经过全面审查，以下设计确认无误：

1. **Detector trait 设计** — `fn name() -> &'static str` + `fn detect() -> Option<DetectionResult>` 接口简洁通用，符合 Rust trait 惯例
2. **LazyLock 静态模式** — 所有检测器使用 `LazyLock<Vec<Regex>>` 延迟编译正则，首次使用前零开销
3. **Scanner::scan_with** — 按名称选择性扫描，适用于已知威胁模型的场景
4. **DataLeakDetector Luhn 校验** — 信用卡号 Luhn 算法实现正确（`is_multiple_of(10)`），有效降低误报
5. **OpenRedirectDetector URL scheme 跳过** — `start > 0 && input.as_bytes()[start - 1] == b':'` 正确跳过 `https://` 等正常 URL
6. **测试覆盖** — 46 个集成测试覆盖全部 27 种检测器 + 边界场景

---

## 五、架构评估

### 5.1 模块结构

```
src/
├── lib.rs          — Detector trait + 公共导出
├── scanner.rs      — Scanner + ScannerBuilder
├── result.rs       — DetectionResult, Severity, AttackCategory
├── injection/      — 10 个注入检测器
├── protocol/       — 9 个协议检测器
├── data/           — 5 个数据检测器
└── file/           — 3 个文件检测器
```

**评分**: 优秀。模块划分清晰，每个检测器独立文件，`mod.rs` 统一导出。

### 5.2 代码模式一致性

所有 27 个检测器遵循统一模式：
1. `LazyLock<Vec<Regex>>` 静态编译正则
2. 零大小的结构体实现 `Detector` trait
3. `detect()` 方法遍历模式，首次匹配即返回

**评分**: 优秀。高一致性使新增检测器成本极低。

---

## 六、仍需关注的改进建议

### 6.1 误报风险较高的模式（未修改）

以下模式在生产环境中可能产生误报，建议根据实际使用场景评估是否保留：

| 检测器 | 模式 | 风险 | 严重度 |
|--------|------|------|--------|
| `command_injection` | `` r"`[^`]+`" `` | 匹配任何反引号内容，Markdown 代码块会误触发 | 高 |
| `command_injection` | `r"&&\s*\w+"` | 合法布尔表达式 `if x && y` 会误触发 | 高 |
| `ssti` | `r"\{\{.*?\}\}"` | 合法模板语法（Vue/Mustache/Jinja2）会误触发 | 中 |
| `ssti` | `r"\$\{.*?\}"` | JS 模板字面量、Shell 变量等正常使用会误触发 | 中 |
| `sql_injection` | `r"(?i)SELECT\s+\*"` | 文档中的 SQL 示例会误触发 | 低 |

### 6.2 缺少单元测试

当前仅有 `tests/integration_test.rs` 集成测试，各检测器模块没有内部单元测试。建议为每个检测器添加 `#[cfg(test)]` 模块测试覆盖：
- 空字符串输入
- 纯正常文本
- 边界值（超长输入、特殊字符）
- 已知误报案例

### 6.3 输入长度限制

无输入长度检查。恶意超长输入可能导致正则回溯性能问题（ReDoS）。建议在 `Scanner::scan()` 添加入口长度限制（如 1MB）。

### 6.4 缺少基准测试

无 `benches/` 目录。建议添加 criterion 基准测试，对比 27 个检测器的扫描性能。

---

## 七、修复统计

| 类别 | 数量 |
|------|------|
| 误报模式移除（本次） | 7 个正则模式（JNDI 4 + data_leak 1 + request_smuggling 2） |
| 前次 Clippy 修复 | 4 |
| 前次死代码删除 | 2 项 |
| 格式化修复 | 24 文件 |
| **当前测试结果** | **46/46 通过** |
| **当前 Clippy 警告** | **0** |

---

## 八、修改文件清单

| 文件 | 修改类型 |
|------|----------|
| `src/injection/jndi_injection.rs` | 移除 4 个裸协议模式（ldap://, rmi://, dns://, ldaps://） |
| `src/file/data_leak.rs` | 移除 JWT 令牌模式（职责回归 jwt_attack） |
| `src/protocol/request_smuggling.rs` | 移除 Content-Length: 0 和 chunked 终止符模式 |

---

## 九、总结

security-rust 是一个结构良好、代码规范的 Rust 安全库。本轮审查聚焦于**降低误报率**，移除了 7 个过于宽泛的正则模式：

1. **JNDI 检测器** — 裸协议 URL 模式被更精确的 `${jndi:...}` 模式完全覆盖
2. **数据泄露检测器** — JWT 令牌检测回归专门的 jwt_attack 检测器
3. **请求走私检测器** — 合法 HTTP 协议元素不再被误报

所有修改已通过 46 个测试验证，Clippy 零警告。建议后续关注命令注入检测器和 SSTI 检测器中的宽泛模式，根据实际使用场景决定是否进一步调整。
