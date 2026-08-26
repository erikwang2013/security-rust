<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# مرجع API لـ security-rust

[中文](../../README.md) | [English](../en/API.md) | [한국어](../ko/API.md) | [Русский](../ru/API.md) | [Deutsch](../de/API.md) | [Français](../fr/API.md) | [Español](../es/API.md) | [Português](../pt/API.md) | [हिन्दी](../hi/API.md) | [বাংলা](../bn/API.md) | [Bahasa Indonesia](../id/API.md) | [日本語](../ja/API.md) | [العربية (本页)](./API.md)

---

## Trait الأساسي

### `Detector`

العقد الوحيد لجميع الكاشفات:

```rust
pub trait Detector {
    fn name(&self) -> &str;
    fn detect(&self, input: &str) -> Option<DetectionResult>;
}
```

- `name()` — اسم الكاشف (مثل `"xss"` و`"sql_injection"`)
- `detect()` — يفحص المدخل، ويعيد `Some(DetectionResult)` عند الإيجابية، و`None` عند عدم وجود إصابة

## بنية نتيجة الكشف

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

### التثبيت

```toml
[dependencies]
security-rust = "1.0.4"
```

### بداية سريعة

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

### الفحص الانتقائي

```rust
let scanner = Scanner::default();

// 只运行指定的检测器
let results = scanner.scan_with(
    "1 UNION SELECT password FROM users",
    &["sql_injection", "xss"],
);
```

### الإعدادات المخصصة

```rust
use security_rust::injection::{XssDetector, SqlInjectionDetector};

// 通过 builder 只装配需要的检测器
let scanner = Scanner::builder()
    .with_detector(Box::new(XssDetector))
    .with_detector(Box::new(SqlInjectionDetector))
    .build();
```

### عرض الخطورة

```rust
use security_rust::Severity;

let r = &results[0];
println!("{}", r.severity);  // CRITICAL | HIGH | MEDIUM | LOW
```

## مسارات الوحدات

| الوحدة | المسار | عدد الكاشفات |
|------|------|---------|
| النواة | `src/lib.rs` `result.rs` `scanner.rs` | — |
| الحقن | `src/injection/` | 10 |
| البروتوكول | `src/protocol/` | 9 |
| البيانات | `src/data/` | 5 |
| الملفات | `src/file/` | 3 |

## الأداء

مع بناء Release، يفحص الكاشف الواحد خلال ~100 نانوثانية في كل مرة (مع تجميع RegexSet مسبقًا)، وفحص جميع الكاشفات الـ 27 يستغرق ~5 ميكروثانية في كل مرة. مناسب لسيناريوهات الإنتاجية العالية (بوابات API وخطوط أنابيب السجلات).
