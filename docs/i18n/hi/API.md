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

> `session` और `throttle` जानबूझकर यह trait लागू नहीं करते — उनका इनपुट मिश्रित है (token + fingerprint + लोकेशन + समय), जिसे `Detector::detect(&str)` व्यक्त नहीं कर सकता। नीचे «स्टेटफुल मॉड्यूल और जोखिम स्कोरिंग» देखें।

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
security-rust = "2.0.0"
```

### त्वरित शुरुआत

```rust
use security_rust::Scanner;

fn main() {
    // शून्य कॉन्फ़िगरेशन: सभी 32 डिटेक्टर इकट्ठा करें
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

बाकी स्टेट लेबल भी `Display` लागू करते हैं और बड़े अक्षरों में छपते हैं: `Decision` (`ALLOW` / `CHALLENGE` / `BLOCK`), `SessionThreat` (जैसे `impossible travel (11205 km/h)`), `AttackCategory` (छोटे अक्षरों में, जैसे `injection`), `ThrottleDecision` (`ALLOW` / `BANNED` / `UNAVAILABLE`), `ThrottleOutcome` (`ALLOW` / `BANNED`)।

```rust
println!("{} {}", verdict.decision, verdict.threats.len());  // BLOCK 2
```

## स्टेटफुल मॉड्यूल और जोखिम स्कोरिंग

ये तीनों मॉड्यूल सीधे क्रेट रूट से उपलब्ध हैं। `session` और `throttle` जानबूझकर `Detector` trait लागू नहीं करते, क्योंकि उनका इनपुट मिश्रित है। कोई नई बाहरी निर्भरता नहीं जुड़ती: token और signature (MAC) कॉलर देता है, और लोकेशन पार्स करना भी कॉलर की ज़िम्मेदारी है।

### `session` — सत्र सुरक्षा

```rust
use security_rust::session::{MemoryStore, RequestContext, SessionConfig, SessionGuard};

let guard = SessionGuard::new(MemoryStore::new(), SessionConfig::default());

let v = guard.bind(&ctx, now)?;        // Result<SessionVerdict, SessionError>
let v = guard.verify(&ctx, now);       // SessionVerdict
guard.revoke(token)?;                  // Result<(), StoreError>
let n = guard.revoke_all(subject)?;    // Result<usize, StoreError>
guard.rotate(old, new, &ctx, now)?;    // Result<(), SessionError>
```

- `RequestContext` फ़ील्ड: `token`, `subject`, `fingerprint`, `location`, `coords`, `signature`, `at`
- `SessionVerdict` फ़ील्ड: `decision`, `severity: Option<Severity>` (अनुमति पर `None`), `threats`
- `subject` **केवल `bind` उपयोग करता है, `verify` इसे पूरी तरह अनदेखा करता है**: हर अनुरोध की पहचान हमेशा सर्वर के `SessionRecord` से आती है (भिन्न-स्थान इतिहास `record.subject` पर जुड़ता है), और अनुरोधकर्ता का भेजा `subject` अविश्वसनीय है; इसलिए मिडलवेयर से `subject: ""` भेजना वैध है (`bind` ही गैर-रिक्त मान माँगता है)। इसी कारण **कभी भी** अनुरोध हेडर से लिया गया उपयोगकर्ता-पहचानकर्ता यहाँ न रखें — वह आज निर्णय तक नहीं पहुँचता, पर भविष्य का रिफ़ैक्टर इसे बनाए रखने के लिए बाध्य नहीं है।
- `Decision`: `Allow` | `Challenge` | `Block`
- स्टोर उपलब्ध न होने पर परिणाम `Decision::Block` (कारण `StoreUnavailable`) होता है — यानी **fail-closed**, कोई रास्ता पार नहीं जाता
- `SessionConfig` डिफ़ॉल्ट: `ttl_secs` = 3600, `impossible_travel_kmh` = 900.0, `timestamp_skew_secs` = 300
- स्टोर trait `SessionStore` से अमूर्त है, तैयार कार्यान्वयन `MemoryStore`; मल्टी-इंस्टेंस डिप्लॉयमेंट के लिए यह trait Redis के लिए लागू करें

### `throttle` — दर सीमित करना

```rust
use security_rust::throttle::{MemoryThrottleStore, Throttle, ThrottleConfig, ThrottleDecision, ThrottleOutcome};

let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());

match throttle.check(key, now) {
    ThrottleDecision::Allow { remaining } => { /* अनुमति */ }
    ThrottleDecision::Banned { until } => { /* प्रतिबंधित */ }
    ThrottleDecision::Unavailable => { /* स्टोर उपलब्ध नहीं */ }
}
// एक साथ कई आयाम जाँचें (जैसे IP + खाता): सबसे सख़्त नतीजा मान्य होता है
let merged = throttle.check_any(&["ip:203.0.113.7", "user:42"], now);  // ThrottleDecision
let outcome = throttle.record_failure(key, now)?;  // Result<ThrottleOutcome, StoreError>
throttle.record_success(key)?;       // Result<(), StoreError>
throttle.reset(key)?;                // Result<(), StoreError>
throttle.purge_expired(now)?;        // Result<usize, StoreError>
```

- `ThrottleConfig` डिफ़ॉल्ट: `threshold` = 5, `window_secs` = 60, `ban_secs` = 900
- `check_any(&[key, ...], now)` कई आयाम मिलाता है: कोई `Banned` हो तो वही जीतता है (सबसे दूर का `until`), वरना `Unavailable`, वरना सबसे छोटे `remaining` वाला `Allow`; खाली सूची पर `Allow { remaining: 0 }`
- `ThrottleOutcome` (`Allow { remaining }` | `Banned { until }`) `record_failure` का परिणाम है; इसमें `Unavailable` नहीं है, क्योंकि स्टोर विफलता वहाँ `Err(StoreError)` बनकर लौटती है
- **जानबूझकर किया गया अपवाद**: स्टोर विफल होने पर `check` / `check_any` `Banned` नहीं, `Unavailable` लौटाते हैं — दर सीमा defense-in-depth है, मुख्य प्रमाणीकरण द्वार नहीं; बैकएंड गड़बड़ी पर सभी उपयोगकर्ताओं को रोकना स्वयं के विरुद्ध DoS है, और निर्णय कॉलर पर छोड़ा गया है
- स्टोर trait `ThrottleStore` से अमूर्त है, तैयार कार्यान्वयन `MemoryThrottleStore`

### `score` — जोखिम स्कोरिंग

```rust
use security_rust::assess;

let results = Scanner::default().scan(input);
let a = assess(&results);
println!("{} {}", a.level, a.score);   // उदाहरण: HIGH 40

let a = Scanner::default().assess(input);  // सीधे RiskAssessment
```

- `RiskLevel`: `None` | `Low` | `Medium` | `High` | `Critical`
- `RiskAssessment` फ़ील्ड: `level`, `score`, `results` (समेकन में शामिल हिट की संख्या)
- भार: Critical = 100, High = 40, Medium = 15, Low = 5

## मॉड्यूल पथ

| मॉड्यूल | पथ | डिटेक्टरों की संख्या |
|------|------|---------|
| कोर | `src/lib.rs` `result.rs` `scanner.rs` | — |
| इंजेक्शन | `src/injection/` | 11 |
| प्रोटोकॉल | `src/protocol/` | 11 |
| डेटा | `src/data/` | 7 |
| फ़ाइल | `src/file/` | 3 |
| सत्र | `src/session/` | — |
| दर सीमा | `src/throttle/` | — |
| जोखिम स्कोरिंग | `src/score.rs` | — |

## प्रदर्शन

Release बिल्ड में, प्रत्येक डिटेक्टर अपने पैटर्न `static PATTERNS: LazyLock<Vec<Regex>>` स्थिर तालिका में रखता है, इसलिए हर regex प्रोसेस के भीतर पहले उपयोग पर एक ही बार कंपाइल होता है और आगे हर कॉल में दोबारा उपयोग होता है, जिसके बाद कोई कंपाइल लागत नहीं रहती। सभी 32 डिटेक्टरों का पूर्ण स्कैन कुछ दसियों माइक्रोसेकंड का होता है, और यह लागत डिटेक्टरों की संख्या तथा इनपुट लंबाई के साथ बढ़ती है; वास्तविक मान अपने हार्डवेयर और लोड पर मापें। उच्च थ्रूपुट परिदृश्यों (API गेटवे, लॉग पाइपलाइन) के लिए उपयुक्त।
