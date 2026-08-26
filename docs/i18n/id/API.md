<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# Referensi API security-rust

[中文](../../README.md) | [English](../en/API.md) | [한국어](../ko/API.md) | [Русский](../ru/API.md) | [Deutsch](../de/API.md) | [Français](../fr/API.md) | [Español](../es/API.md) | [Português](../pt/API.md) | [हिन्दी](../hi/API.md) | [العربية](../ar/API.md) | [বাংলা](../bn/API.md) | [日本語](../ja/API.md) | [Bahasa Indonesia (本页)](./API.md)

---

## Trait Inti

### `Detector`

Satu-satunya kontrak untuk semua detektor:

```rust
pub trait Detector {
    fn name(&self) -> &str;
    fn detect(&self, input: &str) -> Option<DetectionResult>;
}
```

- `name()` — nama detektor (mis. `"xss"`, `"sql_injection"`)
- `detect()` — memindai input; jika terdeteksi, mengembalikan `Some(DetectionResult)`, jika tidak, mengembalikan `None`

## Struktur Hasil Deteksi

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

### Instalasi

```toml
[dependencies]
security-rust = "1.0.4"
```

### Mulai Cepat

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

### Pemindaian Selektif

```rust
let scanner = Scanner::default();

// 只运行指定的检测器
let results = scanner.scan_with(
    "1 UNION SELECT password FROM users",
    &["sql_injection", "xss"],
);
```

### Konfigurasi Kustom

```rust
use security_rust::injection::{XssDetector, SqlInjectionDetector};

// 通过 builder 只装配需要的检测器
let scanner = Scanner::builder()
    .with_detector(Box::new(XssDetector))
    .with_detector(Box::new(SqlInjectionDetector))
    .build();
```

### Menampilkan Severity

```rust
use security_rust::Severity;

let r = &results[0];
println!("{}", r.severity);  // CRITICAL | HIGH | MEDIUM | LOW
```

## Jalur Modul

| Modul | Jalur | Jumlah Detektor |
|------|------|---------|
| Inti | `src/lib.rs` `result.rs` `scanner.rs` | — |
| Injeksi | `src/injection/` | 10 |
| Protokol | `src/protocol/` | 9 |
| Data | `src/data/` | 5 |
| File | `src/file/` | 3 |

## Performa

Pada build Release, pemindaian satu detektor ~100ns/kali (RegexSet pra-kompilasi), pemindaian penuh 27 detektor sekitar ~5μs/kali. Cocok untuk skenario throughput tinggi (gateway API, pipeline log).
