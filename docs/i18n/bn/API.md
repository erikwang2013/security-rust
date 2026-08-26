<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust API রেফারেন্স

[中文](../../README.md) | [English](../en/API.md) | [한국어](../ko/API.md) | [Русский](../ru/API.md) | [Deutsch](../de/API.md) | [Français](../fr/API.md) | [Español](../es/API.md) | [Português](../pt/API.md) | [हिन्दी](../hi/API.md) | [العربية](../ar/API.md) | [Bahasa Indonesia](../id/API.md) | [日本語](../ja/API.md) | [বাংলা (本页)](./API.md)

---

## কোর Trait

### `Detector`

সব ডিটেক্টরের একমাত্র চুক্তি:

```rust
pub trait Detector {
    fn name(&self) -> &str;
    fn detect(&self, input: &str) -> Option<DetectionResult>;
}
```

- `name()` — ডিটেক্টরের নাম (যেমন `"xss"`, `"sql_injection"`)
- `detect()` — ইনপুট স্ক্যান করে, হিট হলে `Some(DetectionResult)` ফেরত দেয়, না হলে `None` ফেরত দেয়

## শনাক্তকরণ ফলাফলের গঠন

```rust
pub struct DetectionResult {
    pub attack_type: String,      // "xss", "sql_injection" ...
    pub category: AttackCategory, // Injection | Protocol | Data | File
    pub severity: Severity,       // Critical | High | Medium | Low
    pub matched_pattern: String,  // ম্যাচ হওয়া নির্দিষ্ট প্যাটার্নের টুকরা
    pub offset: usize,            // ইনপুটে বাইট অফসেট
    pub message: String,          // মানব-পঠনযোগ্য বিবরণ
}
```

## Scanner

### ইনস্টলেশন

```toml
[dependencies]
security-rust = "1.0.4"
```

### দ্রুত শুরু

```rust
use security_rust::Scanner;

fn main() {
    // শূন্য কনফিগারেশন: সব ২৭টি ডিটেক্টর একত্রিত হয়
    let scanner = Scanner::default();

    // ইনপুট স্ক্যান করে, সব শনাক্ত হওয়া আক্রমণ ফেরত দেয়
    let results = scanner.scan("<script>alert('xss')</script>");

    for r in &results {
        println!("[{}] {} — offset: {}, pattern: {}",
            r.severity, r.message, r.offset, r.matched_pattern);
    }
    // আউটপুট:
    // [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
}
```

### সিলেক্টিভ স্ক্যানিং

```rust
let scanner = Scanner::default();

// শুধুমাত্র নির্দিষ্ট ডিটেক্টর চালায়
let results = scanner.scan_with(
    "1 UNION SELECT password FROM users",
    &["sql_injection", "xss"],
);
```

### কাস্টম কনফিগারেশন

```rust
use security_rust::injection::{XssDetector, SqlInjectionDetector};

// builder দিয়ে শুধুমাত্র প্রয়োজনীয় ডিটেক্টর একত্রিত করে
let scanner = Scanner::builder()
    .with_detector(Box::new(XssDetector))
    .with_detector(Box::new(SqlInjectionDetector))
    .build();
```

### গুরুতরতা প্রদর্শন

```rust
use security_rust::Severity;

let r = &results[0];
println!("{}", r.severity);  // CRITICAL | HIGH | MEDIUM | LOW
```

## মডিউল পাথ

| মডিউল | পাথ | ডিটেক্টর সংখ্যা |
|------|------|---------|
| কোর | `src/lib.rs` `result.rs` `scanner.rs` | — |
| ইনজেকশন | `src/injection/` | 10 |
| প্রোটোকল | `src/protocol/` | 9 |
| ডেটা | `src/data/` | 5 |
| ফাইল | `src/file/` | 3 |

## পারফরম্যান্স

Release বিল্ডে, একক ডিটেক্টর স্ক্যান প্রতি স্ক্যান ~100ns (RegexSet প্রি-কম্পাইলড), সম্পূর্ণ ২৭টি ডিটেক্টর স্ক্যান প্রতি স্ক্যান ~5μs। উচ্চ থ্রুপুট পরিস্থিতির জন্য উপযুক্ত (API গেটওয়ে, লগ পাইপলাইন)।
