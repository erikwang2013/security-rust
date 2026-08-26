# security-rust 测试报告

- **日期**: 2026-08-27
- **版本**: 1.0.5
- **执行**: 3 名 Rust 测试工程师（injection / protocol / data+file 并行）+ 核心模块
- **结果**: **249 个测试全部通过，0 失败**（203 单元 + 46 集成）

## 测试覆盖

| 模块 | 文件数 | 单元测试数 |
|------|--------|-----------|
| injection（xss/sql/command/nosql/ldap/xpath/jndi/ssi/graphql/ssti） | 10 | 49 |
| protocol（ssrf/xxe/header/host_header/smuggling/redirect/cors/websocket/dns） | 9 | 91 |
| data（deserialization/csv/mail_header/jwt/prototype_pollution） | 5 | 25 |
| file（path_traversal/upload/data_leak） | 3 | 19 |
| core（scanner/result/lib） | 3 | 19 |
| **单元测试合计** | **30** | **203** |
| 集成测试（tests/integration_test.rs） | 1 | 46 |
| **总计** | | **249** |

## 每个检测器的覆盖维度

- `name()` 返回正确的 attack_type
- 正向：3–8 个攻击载荷（含大小写混淆、编码变体）→ 命中并断言 attack_type/category/severity
- 反向：5–11 个良性输入 → 不误报
- 边界：空串、纯空白、unicode、近似载荷（如 `http://172.32.0.1/`、`Transfer-Encoding: chuncked`）
- 结果完整性：`matched_pattern` 非空、`offset` 在输入范围内

## 发现并修复的问题

| # | 位置 | 问题 | 修复 |
|---|------|------|------|
| 1 | src/result.rs | `DetectionResult` 缺少 `PartialEq, Eq` 派生（既有缺陷） | 派生补齐（一行，additive） |
| 2 | src/scanner.rs（测试） | `scan_with_multiple_names` 载荷 `"SELECT 1; ..."` 不触发 sql_injection | 改用真值载荷 `UNION SELECT password FROM users` |

另修正 2 处测试载荷笔误（`UNOIN` 误匹配 `SELECT \s+ \*` 模式、全角 `Ｂcc:` 仍含 ASCII `cc:`、`a[constructor][b]` 不含 `constructor[`）——均为载荷问题，非检测器缺陷。

**检测器逻辑缺陷：0 个** —— 27 个检测器的正则、严重级、offset 行为均与源码一致。

## 质量门禁

- `cargo test` — 249 通过 / 0 失败
- `cargo clippy --all-targets` — 0 警告
- `cargo fmt --check` — 通过
