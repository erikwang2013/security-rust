<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust API संदर्भ

[中文](../../README.md) | [English](../en/API.md) | [한국어](../ko/API.md) | [Русский](../ru/API.md) | [Deutsch](../de/API.md) | [Français](../fr/API.md) | [Español](../es/API.md) | [Português](../pt/API.md) | [العربية](../ar/API.md) | [বাংলা](../bn/API.md) | [Bahasa Indonesia](../id/API.md) | [日本語](../ja/API.md) | [हिन्दी (本页)](./API.md)

---

## मुख्य Trait

### `Detector`

सभी डिटेक्टरों का एकमात्र अनुबंध:

```rust
pub trait Detector {
    fn name(&self) -> &str;
    fn detect(&self, input: &str) -> Option<DetectionResult>;
}
```

- `name()` — डिटेक्टर का नाम (जैसे `"xss"`, `"sql_injection"`)
- `detect()` — इनपुट स्कैन करता है; हिट होने पर `Some(DetectionResult)` लौटाता है, न होने पर `None` लौटाता है

## पहचान परिणाम संरचना

```rust
pub struct DetectionResult {
    pub attack_type: String,      // "xss", "sql_injection" ...
    pub category: AttackCategory, // Injection | Protocol | Data | File
    pub severity: Severity,       // Critical | High | Medium | Low
    pub matched_pattern: String,  // मिलान किया गया विशिष्ट पैटर्न अंश
    pub offset: usize,            // इनपुट में बाइट ऑफ़सेट
    pub message: String,          // मानव-पठनीय विवरण
}
```

## Scanner

### इंस्टॉलेशन

```toml
[dependencies]
security-rust = "1.0.4"
```

### त्वरित शुरुआत

```rust
use security_rust::Scanner;

fn main() {
    // शून्य कॉन्फ़िगरेशन: सभी 27 डिटेक्टर इकट्ठा करें
    let scanner = Scanner::default();

    // इनपुट स्कैन करें, पता चले सभी हमले लौटाएँ
    let results = scanner.scan("<script>alert('xss')</script>");

    for r in &results {
        println!("[{}] {} — offset: {}, pattern: {}",
            r.severity, r.message, r.offset, r.matched_pattern);
    }
    // आउटपुट:
    // [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
}
```

### चयनात्मक स्कैनिंग

```rust
let scanner = Scanner::default();

// केवल निर्दिष्ट डिटेक्टर चलाएँ
let results = scanner.scan_with(
    "1 UNION SELECT password FROM users",
    &["sql_injection", "xss"],
);
```

### कस्टम कॉन्फ़िगरेशन

```rust
use security_rust::injection::{XssDetector, SqlInjectionDetector};

// builder के माध्यम से केवल आवश्यक डिटेक्टर इकट्ठा करें
let scanner = Scanner::builder()
    .with_detector(Box::new(XssDetector))
    .with_detector(Box::new(SqlInjectionDetector))
    .build();
```

### गंभीरता प्रदर्शन

```rust
use security_rust::Severity;

let r = &results[0];
println!("{}", r.severity);  // CRITICAL | HIGH | MEDIUM | LOW
```

## मॉड्यूल पथ

| मॉड्यूल | पथ | डिटेक्टरों की संख्या |
|------|------|---------|
| कोर | `src/lib.rs` `result.rs` `scanner.rs` | — |
| इंजेक्शन | `src/injection/` | 10 |
| प्रोटोकॉल | `src/protocol/` | 9 |
| डेटा | `src/data/` | 5 |
| फ़ाइल | `src/file/` | 3 |

## प्रदर्शन

Release बिल्ड में, एकल डिटेक्टर स्कैन ~100ns/बार (RegexSet प्रीकंपाइल्ड), सभी 27 डिटेक्टरों के साथ पूर्ण स्कैन ~5μs/बार। उच्च थ्रूपुट परिदृश्यों (API गेटवे, लॉग पाइपलाइन) के लिए उपयुक्त।
