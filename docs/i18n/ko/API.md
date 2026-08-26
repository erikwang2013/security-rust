<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust API 참조

[中文](../../README.md) | [English](../en/API.md) | [Русский](../ru/API.md) | [Deutsch](../de/API.md) | [Français](../fr/API.md) | [Español](../es/API.md) | [Português](../pt/API.md) | [हिन्दी](../hi/API.md) | [العربية](../ar/API.md) | [বাংলা](../bn/API.md) | [Bahasa Indonesia](../id/API.md) | [日本語](../ja/API.md) | [한국어 (本页)](./API.md)

---

## 핵심 Trait

### `Detector`

모든 탐지기의 유일한 계약:

```rust
pub trait Detector {
    fn name(&self) -> &str;
    fn detect(&self, input: &str) -> Option<DetectionResult>;
}
```

- `name()` — 탐지기 이름 (예: `"xss"`, `"sql_injection"`)
- `detect()` — 입력을 스캔하여 탐지되면 `Some(DetectionResult)` 반환, 미탐지 시 `None` 반환

## 탐지 결과 구조

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

### 설치

```toml
[dependencies]
security-rust = "1.0.4"
```

### 빠른 시작

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

### 선택적 스캔

```rust
let scanner = Scanner::default();

// 只运行指定的检测器
let results = scanner.scan_with(
    "1 UNION SELECT password FROM users",
    &["sql_injection", "xss"],
);
```

### 커스텀 구성

```rust
use security_rust::injection::{XssDetector, SqlInjectionDetector};

// 通过 builder 只装配需要的检测器
let scanner = Scanner::builder()
    .with_detector(Box::new(XssDetector))
    .with_detector(Box::new(SqlInjectionDetector))
    .build();
```

### 심각도 표시

```rust
use security_rust::Severity;

let r = &results[0];
println!("{}", r.severity);  // CRITICAL | HIGH | MEDIUM | LOW
```

## 모듈 경로

| 모듈 | 경로 | 탐지기 수 |
|------|------|---------|
| 핵심 | `src/lib.rs` `result.rs` `scanner.rs` | — |
| 인젝션 | `src/injection/` | 10 |
| 프로토콜 | `src/protocol/` | 9 |
| 데이터 | `src/data/` | 5 |
| 파일 | `src/file/` | 3 |

## 성능

Release 빌드에서 단일 탐지기 스캔은 약 ~100ns/회(RegexSet 사전 컴파일), 전체 27개 탐지기 스캔은 약 ~5μs/회다. 높은 처리량 시나리오(API 게이트웨이, 로그 파이프라인)에 적합하다.
