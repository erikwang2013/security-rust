<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust API 参考

[中文](../README.md) | [English](./i18n/en/API.md) | [한국어](./i18n/ko/API.md) | [Русский](./i18n/ru/API.md) | [Deutsch](./i18n/de/API.md) | [Français](./i18n/fr/API.md) | [Español](./i18n/es/API.md) | [Português](./i18n/pt/API.md) | [हिन्दी](./i18n/hi/API.md) | [العربية](./i18n/ar/API.md) | [বাংলা](./i18n/bn/API.md) | [Bahasa Indonesia](./i18n/id/API.md) | [日本語](./i18n/ja/API.md)

---

## 核心 Trait

### `Detector`

所有检测器的唯一契约：

```rust
pub trait Detector {
    fn name(&self) -> &str;
    fn detect(&self, input: &str) -> Option<DetectionResult>;
}
```

- `name()` — 检测器名称（如 `"xss"`、`"sql_injection"`）
- `detect()` — 扫描输入，命中则返回 `Some(DetectionResult)`，未命中返回 `None`

## 检测结果结构

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

## Scanner

### 安装

```toml
[dependencies]
security-rust = "1.0.4"
```

### 快速开始

```rust
use security_rust::Scanner;

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
use security_rust::injection::{XssDetector, SqlInjectionDetector};

// 通过 builder 只装配需要的检测器
let scanner = Scanner::builder()
    .with_detector(Box::new(XssDetector))
    .with_detector(Box::new(SqlInjectionDetector))
    .build();
```

### 严重度展示

```rust
use security_rust::Severity;

let r = &results[0];
println!("{}", r.severity);  // CRITICAL | HIGH | MEDIUM | LOW
```

## 模块路径

| 模块 | 路径 | 检测器数 |
|------|------|---------|
| 核心 | `src/lib.rs` `result.rs` `scanner.rs` | — |
| 注入 | `src/injection/` | 10 |
| 协议 | `src/protocol/` | 9 |
| 数据 | `src/data/` | 5 |
| 文件 | `src/file/` | 3 |

## 性能

Release 构建下，单检测器扫描 ~100ns/次（RegexSet 预编译），全量 27 检测器扫描约 ~5μs/次。适合高吞吐量场景（API 网关、日志管道）。
