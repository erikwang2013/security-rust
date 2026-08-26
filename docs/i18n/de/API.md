<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust API-Referenz

[中文](../../README.md) | [English](../en/API.md) | [한국어](../ko/API.md) | [Русский](../ru/API.md) | [Français](../fr/API.md) | [Español](../es/API.md) | [Português](../pt/API.md) | [हिन्दी](../hi/API.md) | [العربية](../ar/API.md) | [বাংলা](../bn/API.md) | [Bahasa Indonesia](../id/API.md) | [日本語](../ja/API.md) | [Deutsch (本页)](./API.md)

---

## Kern-Trait

### `Detector`

Der einzige Vertrag aller Detektoren:

```rust
pub trait Detector {
    fn name(&self) -> &str;
    fn detect(&self, input: &str) -> Option<DetectionResult>;
}
```

- `name()` — Name des Detektors (z. B. `"xss"`, `"sql_injection"`)
- `detect()` — scannt die Eingabe; bei Treffer wird `Some(DetectionResult)` zurückgegeben, sonst `None`

## Struktur des Erkennungsergebnisses

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

### Installation

```toml
[dependencies]
security-rust = "1.0.4"
```

### Schnellstart

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

### Selektives Scannen

```rust
let scanner = Scanner::default();

// 只运行指定的检测器
let results = scanner.scan_with(
    "1 UNION SELECT password FROM users",
    &["sql_injection", "xss"],
);
```

### Benutzerdefinierte Konfiguration

```rust
use security_rust::injection::{XssDetector, SqlInjectionDetector};

// 通过 builder 只装配需要的检测器
let scanner = Scanner::builder()
    .with_detector(Box::new(XssDetector))
    .with_detector(Box::new(SqlInjectionDetector))
    .build();
```

### Schweregrad-Anzeige

```rust
use security_rust::Severity;

let r = &results[0];
println!("{}", r.severity);  // CRITICAL | HIGH | MEDIUM | LOW
```

## Modulpfade

| Modul | Pfad | Anzahl Detektoren |
|------|------|---------|
| Kern | `src/lib.rs` `result.rs` `scanner.rs` | — |
| Injection | `src/injection/` | 10 |
| Protokoll | `src/protocol/` | 9 |
| Daten | `src/data/` | 5 |
| Datei | `src/file/` | 3 |

## Leistung

In einem Release-Build dauert ein Scan mit einem einzelnen Detektor ~100 ns pro Eingabe (vorcompilierte RegexSet); ein Scan mit allen 27 Detektoren etwa ~5 μs pro Eingabe. Geeignet für Szenarien mit hohem Durchsatz (API-Gateways, Log-Pipelines).
