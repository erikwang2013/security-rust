# 代码审查报告 — attack-detection

**日期**: 2026-07-29  
**审查范围**: 全部源码 (27 个检测器 + 核心框架 + 测试)  
**测试结果**: 46/46 全部通过  
**Clippy**: 零警告  
**格式化**: cargo fmt 已通过  

---

## 一、项目概况

attack-detection 是一个 Rust 安全攻击检测库，覆盖 4 大类 27 种攻击向量：

| 分类 | 检测器 | 数量 |
|------|--------|------|
| 注入 (Injection) | XSS, SQL注入, 命令注入, NoSQL注入, LDAP注入, XPath注入, JNDI注入, SSI注入, GraphQL注入, SSTI | 10 |
| 协议 (Protocol) | SSRF, XXE, Header注入, Host Header, 请求走私, 开放重定向, CORS, WebSocket, DNS重绑定 | 9 |
| 数据 (Data) | 反序列化, CSV注入, 邮件头注入, JWT攻击, 原型污染 | 5 |
| 文件 (File) | 路径穿越, 恶意上传, 数据泄露 | 3 |

---

## 二、已修复的问题

### 2.1 Clippy 警告修复 (4处)

| # | 文件 | 行 | 问题 | 修复 |
|---|------|----|------|------|
| 1 | `src/file/data_leak.rs` | 43 | `sum % 10 == 0` 手写取模 | 改用 `sum.is_multiple_of(10)` |
| 2 | `src/file/data_leak.rs` | 54-65 | 嵌套 if 可合并 | 合并为 `if let Some(m) = ... && luhn_valid(...)` |
| 3 | `src/scanner.rs` | 12 | `Scanner::default()` 应实现标准 trait | 改为 `impl Default for Scanner`，添加 `new()` 便捷方法 |
| 4 | `src/scanner.rs` | 67-71 | `scan_with` 中嵌套 if 可合并 | 合并为 `if names.contains(...) && let Some(...) = ...` |

### 2.2 死代码清理

| # | 文件 | 问题 | 修复 |
|---|------|------|------|
| 5 | `src/result.rs` | `AttackCategory::Http` 变体定义但全项目零引用 | 删除 `Http` 变体 |
| 6 | `src/scanner.rs` | `ScannerBuilder` 含 8 个保留字段 + 8 个 builder 方法，`build()` 完全忽略这些配置 | 删除所有未使用的保留字段及方法 |

### 2.3 代码格式化

`cargo fmt` 修复了全部 24 个文件的导入顺序和长行换行问题（`use crate::` 应在 `use std::` 之前）。

---

## 三、已验证正确的设计

以下方面经过审查确认无误：

1. **Detector trait 设计** — `fn name() -> &'static str` + `fn detect() -> Option<DetectionResult>` 接口简洁通用
2. **LazyLock 静态模式** — 所有检测器用 `LazyLock<Vec<Regex>>` 延迟编译正则，避免启动开销
3. **Scanner::scan_with** — 按名称选择性扫描，结果聚合正确
4. **DataLeakDetector** — 信用卡号 Luhn 校验算法实现正确，减少误报
5. **OpenRedirectDetector** — URL scheme 跳过逻辑 (`start > 0 && input.as_bytes()[start - 1] == b':'`) 边界安全
6. **测试覆盖** — 46 个集成测试覆盖全部 27 种检测器 + 边界场景（空输入、干净输入、多检测、builder空、scan_with过滤）

---

## 四、潜在改进建议（未修改）

以下为审查中发现的值得关注但未在此次修改的问题：

### 4.1 误报风险较高的模式

| 检测器 | 模式 | 风险 |
|--------|------|------|
| `command_injection` | `` r"`[^`]+`" `` | 匹配任何反引号内容，Markdown 代码块会误触发 |
| `command_injection` | `r"&&\s*\w+"` | 合法布尔表达式 `if x && y` 会误触发 |
| `ssti` | `r"\{\{.*?\}\}"` | 合法模板语法（Vue/Mustache）会误触发 |
| `sql_injection` | `r"(?i)SELECT\s+\*"` | 文档中提及 SQL 语法会误触发 |

**建议**: 为生产环境使用添加可配置的检测器开关（已有 `scan_with` 可按名称选择，但缺少全局配置）。

### 4.2 缺少单元测试

当前仅有 `tests/integration_test.rs` 集成测试，各检测器模块内部没有单元测试。

**建议**: 为每个检测器添加 `#[cfg(test)]` 模块测试，覆盖边界情况（空字符串、纯数字、超长输入等）。

### 4.3 输入长度限制

无输入长度检查。恶意超长输入可能导致正则回溯性能问题（ReDoS）。

**建议**: 在 `Scanner::scan()` 入口添加可配置的输入长度上限（如 1MB）。

### 4.4 缺失 `Send + Sync` 验证

`Detector` trait 要求 `Send + Sync`，但无编译期测试验证。

**建议**: 添加静态断言验证 Scanner 满足 Send + Sync。

---

## 五、修复统计

| 类别 | 数量 |
|------|------|
| Clippy 警告修复 | 4 |
| 死代码删除 | 2 (1 枚举变体 + 8 字段/方法) |
| 格式化修复 | 24 文件 |
| 测试结果 | 46/46 通过 |
| **最终 Clippy 警告** | **0** |

---

## 六、修改文件清单

| 文件 | 修改类型 |
|------|----------|
| `src/scanner.rs` | `Default` trait 实现 + 嵌套if合并 + Builder死代码删除 |
| `src/file/data_leak.rs` | `is_multiple_of` + 嵌套if合并 |
| `src/result.rs` | 删除未使用的 `Http` 变体 |
| `src/data/*.rs` (5文件) | fmt 导入排序 |
| `src/injection/*.rs` (10文件) | fmt 导入排序 |
| `src/protocol/*.rs` (9文件) | fmt 导入排序 |
| `src/file/*.rs` (3文件) | fmt 导入排序 |
| `tests/integration_test.rs` | fmt 长行换行 |
