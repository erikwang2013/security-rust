<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust API リファレンス

[中文](../../README.md) | [English](../en/API.md) | [한국어](../ko/API.md) | [Русский](../ru/API.md) | [Deutsch](../de/API.md) | [Français](../fr/API.md) | [Español](../es/API.md) | [Português](../pt/API.md) | [हिन्दी](../hi/API.md) | [العربية](../ar/API.md) | [বাংলা](../bn/API.md) | [Bahasa Indonesia](../id/API.md) | [日本語 (本页)](./API.md)

---

## コア Trait

### `Detector`

全検出器の唯一の契約:

```rust
pub trait Detector {
    fn name(&self) -> &str;
    fn detect(&self, input: &str) -> Option<DetectionResult>;
}
```

- `name()` — 検出器名（例: `"xss"`、`"sql_injection"`）
- `detect()` — 入力をスキャンし、ヒット時は `Some(DetectionResult)` を、未ヒット時は `None` を返す

## 検出結果の構造

```rust
pub struct DetectionResult {
    pub attack_type: String,      // "xss", "sql_injection" ...
    pub category: AttackCategory, // Injection | Protocol | Data | File
    pub severity: Severity,       // Critical | High | Medium | Low
    pub matched_pattern: String,  // マッチした具体的なパターン断片
    pub offset: usize,            // 入力内のバイトオフセット
    pub message: String,          // 人間が読める説明
}
```

## Scanner

### インストール

```toml
[dependencies]
security-rust = "1.0.4"
```

### クイックスタート

```rust
use security_rust::Scanner;

fn main() {
    // ゼロ設定: 全 27 個の検出器を装備
    let scanner = Scanner::default();

    // 入力をスキャンし、検出されたすべての攻撃を返す
    let results = scanner.scan("<script>alert('xss')</script>");

    for r in &results {
        println!("[{}] {} — offset: {}, pattern: {}",
            r.severity, r.message, r.offset, r.matched_pattern);
    }
    // 出力:
    // [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
}
```

### 選択的スキャン

```rust
let scanner = Scanner::default();

// 指定した検出器のみ実行
let results = scanner.scan_with(
    "1 UNION SELECT password FROM users",
    &["sql_injection", "xss"],
);
```

### カスタム設定

```rust
use security_rust::injection::{XssDetector, SqlInjectionDetector};

// builder で必要な検出器だけを装備
let scanner = Scanner::builder()
    .with_detector(Box::new(XssDetector))
    .with_detector(Box::new(SqlInjectionDetector))
    .build();
```

### 重大度表示

```rust
use security_rust::Severity;

let r = &results[0];
println!("{}", r.severity);  // CRITICAL | HIGH | MEDIUM | LOW
```

## モジュールパス

| モジュール | パス | 検出器数 |
|------|------|---------|
| コア | `src/lib.rs` `result.rs` `scanner.rs` | — |
| インジェクション | `src/injection/` | 10 |
| プロトコル | `src/protocol/` | 9 |
| データ | `src/data/` | 5 |
| ファイル | `src/file/` | 3 |

## 性能

Release ビルドで、単一検出器のスキャンは ~100ns/回（RegexSet プリコンパイル済み）、全 27 検出器でのスキャンは約 ~5μs/回です。高スループットのシナリオ（API ゲートウェイ、ログパイプライン）に適しています。
