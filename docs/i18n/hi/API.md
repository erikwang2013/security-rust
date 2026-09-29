<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust API संदर्भ

[中文](../../../README.md) | [English](../en/API.md) | [한국어](../ko/API.md) | [Русский](../ru/API.md) | [Deutsch](../de/API.md) | [Français](../fr/API.md) | [Español](../es/API.md) | [Português](../pt/API.md) | [العربية](../ar/API.md) | [বাংলা](../bn/API.md) | [Bahasa Indonesia](../id/API.md) | [日本語](../ja/API.md) | [हिन्दी (本页)](./API.md)

---

## मुख्य Trait

### `Detector`

सभी डिटेक्टरों का एकमात्र अनुबंध:

```rust
pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
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

## दो स्तर के संकेत: मज़बूत और कमज़ोर

32 में से 18 डिटेक्टर अपने पैटर्न को दो स्तरों में बाँटते हैं (स्रोत में `STRONG_PATTERNS` / `WEAK_PATTERNS` स्टैटिक)। `DetectionResult` की फ़ील्ड-संरचना नहीं बदली — जो बदला है वह `severity` का मान है:

| स्तर | कसौटी | `severity` | क्या एक अकेली हिट अस्वीकृति-रेखा पार कर सकती है |
|------|------|-----------|------------------|
| **मज़बूत संकेत** | स्वयं यह आकार केवल हमले से ही आ सकता है | डिटेक्टर की घोषित गंभीरता | हाँ |
| **कमज़ोर संकेत** | टोकन का महज़ «दिखना» — जो सामान्य सामग्री में हर जगह मिलता है | सदैव `Severity::Low` (5 अंक) | **नहीं** |

एक ही डिटेक्टर, एक ही `attack_type`, केवल `severity` अलग; `detect()` पहले मज़बूत स्तर आज़माता है और उसके बाद कमज़ोर, इसलिए **प्रत्येक डिटेक्टर अधिकतम एक ही परिणाम लौटाता है**। कमज़ोर संकेत फिर भी पकड़े जाते हैं और चुपचाप छूटते नहीं।

`DetectionResult` स्वयं स्तर नहीं बताता — यह जानने के लिए कि कोई हिट मज़बूत है या कमज़ोर, `severity == Severity::Low` देख लेना पर्याप्त है (कमज़ोर स्तर ही `Low` रिपोर्ट करने वाला एकमात्र स्रोत है)। संदर्भ पाइपलाइन की अस्वीकृति-रेखा 40 अंक है (`risk.level >= RiskLevel::High`, देखें [`examples/waf.rs:166`](../../../examples/waf.rs)); एक अकेले कमज़ोर संकेत का मूल्य 5 है और वह इस शाखा तक नहीं पहुँचता।

कमज़ोर संकेतों के पीछे का हमला देखने का साधन `assess()` है, जो कई डिटेक्टरों की हिट जोड़ता है; और **कमज़ोर संकेत के लिए यही एकमात्र मार्ग है** — 5 अंक 40 की रेखा कभी नहीं पार करते, यह केवल कई (अलग-अलग डिटेक्टरों की) हिट का जोड़ करता है। इसीलिए सभी आयामों का इनपुट एक ही `Scanner` को देना किसी एक फ़ील्ड को स्कैन करने से ज़्यादा कुछ दिखाता है; और इसके विपरीत, एक छोटा फ़ील्ड स्कैन करते समय कमज़ोर संकेतों के लिए कोई कार्रवाई आवश्यक नहीं।

```rust
let scanner = Scanner::default();

// तीन कमज़ोर संकेत तीन अलग डिटेक्टरों में पड़े: Medium (15 अंक) तक केवल जोड़ पहुँचता है, High तक नहीं
let a = scanner.assess("<script src=\"/app.js\"></script>\n../config\n__proto__");
assert_eq!(a.results, 3);
assert_eq!(a.score, 15);
assert_eq!(a.level, RiskLevel::Medium);
```

कमज़ोर स्तर पर डाले गए आकारों के उदाहरण (पूरी सूची प्रत्येक डिटेक्टर के `WEAK_PATTERNS` में): `<script src=...>`, एक-स्तरीय `../`, पंक्ति के आरंभ में `-2`, नंगा `__proto__`, `${env:}`, `X-Forwarded-Host`, `Host: localhost`, नंगा `10.0.0.5`, `//evil.com`, `information_schema`।

कसौटी **आकार** है, फ़ाइल का नाम नहीं: उसी `../` के लिए एक स्तर (`../x`) `Low` रिपोर्ट होता है और कई स्तर (`../../`) `Critical` ([`src/file/path_traversal.rs`](../../../src/file/path_traversal.rs))। प्रत्येक डिटेक्टर कितना ऊपर पहुँच सकता है, यह नीचे की तालिकाओं और [README](./README.md) की सुविधा-तालिकाओं में है।

## Scanner

### इंस्टॉलेशन

```toml
[dependencies]
security-rust = "3.0.0"
```

### त्वरित शुरुआत

```rust
use security_rust::Scanner;

fn main() {
    // शून्य कॉन्फ़िगरेशन: सभी 32 डिटेक्टर इकट्ठा करें
    let scanner = Scanner::default();

    // इनपुट स्कैन करें, पता चले सभी हमले लौटाएँ (प्रति डिटेक्टर अधिकतम एक)
    let results = scanner.scan("<img src=x onerror=alert(1)>");

    for r in &results {
        println!("[{}] {} — offset: {}, pattern: {}",
            r.severity, r.message, r.offset, r.matched_pattern);
    }
    // आउटपुट:
    // [CRITICAL] XSS cross-site scripting detected — offset: 11, pattern: onerror=

    // कमज़ोर संकेत उसी डिटेक्टर और उसी attack_type से आता है, केवल severity = Low अलग होती है
    let weak = scanner.scan("<script src=\"/app.js\"></script>");
    // [LOW] XSS tag present (weak signal) — offset: 0, pattern: <script>
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
use security_rust::session::{MemoryStore, RequestContext, SessionConfig, SessionGuard, SessionStore};

let guard = SessionGuard::new(MemoryStore::new(), SessionConfig::default());

impl<S: SessionStore> SessionGuard<S> {
    pub fn bind(&self, ctx: &RequestContext, now: u64) -> Result<SessionVerdict, SessionError>;
    pub fn verify(&self, ctx: &RequestContext, now: u64) -> SessionVerdict;
    pub fn revoke(&self, token: &str) -> Result<(), StoreError>;
    pub fn revoke_all(&self, subject: &str) -> Result<usize, StoreError>;
    pub fn rotate(&self, old: &str, new: &str, ctx: &RequestContext, now: u64) -> Result<(), SessionError>;
    pub fn purge_expired(&self, now: u64) -> Result<usize, StoreError>;
}
```

- `RequestContext` फ़ील्ड: `token`, `subject`, `fingerprint`, `location`, `coords`, `signature`, `at`
- `SessionVerdict` फ़ील्ड: `decision`, `severity: Option<Severity>` (अनुमति पर `None`), `threats`
- `subject` **केवल `bind` उपयोग करता है, `verify` इसे पूरी तरह अनदेखा करता है**: हर अनुरोध की पहचान हमेशा सर्वर के `SessionRecord` से आती है (भिन्न-स्थान इतिहास `record.subject` पर जुड़ता है), और अनुरोधकर्ता का भेजा `subject` अविश्वसनीय है; इसलिए मिडलवेयर से `subject: ""` भेजना वैध है (`bind` ही गैर-रिक्त मान माँगता है)। इसी कारण **कभी भी** अनुरोध हेडर से लिया गया उपयोगकर्ता-पहचानकर्ता यहाँ न रखें — वह आज निर्णय तक नहीं पहुँचता, पर भविष्य का रिफ़ैक्टर इसे बनाए रखने के लिए बाध्य नहीं है।
- `Decision`: `Allow` | `Challenge` | `Block`
- स्टोर उपलब्ध न होने पर परिणाम `Decision::Block` (कारण `StoreUnavailable`) होता है — यानी **fail-closed**, कोई रास्ता पार नहीं जाता
- `SessionConfig` डिफ़ॉल्ट: `ttl_secs` = 3600, `impossible_travel_kmh` = 900.0, `timestamp_skew_secs` = 300
- स्टोर trait `SessionStore` से अमूर्त है, तैयार कार्यान्वयन `MemoryStore`; मल्टी-इंस्टेंस डिप्लॉयमेंट के लिए यह trait Redis के लिए लागू करें
- `purge_expired(now)` उन सत्रों को हटाता है जिनके `expires_at <= now` हैं, तथा उन सभी `subject` का पूरा लॉगिन इतिहास भी जिनका अंतिम लॉगिन-बिंदु `now - LOGIN_HISTORY_KEEP_SECS` (7 दिन) से पुराना है। **लौटाया गया मान केवल सत्रों की गिनती करता है**, पुनःप्राप्त लॉगिन इतिहास की नहीं
- **`MemoryStore` में `subject` की संख्या असीमित है**: प्रत्येक `subject` के लॉगिन इतिहास की लंबाई `MAX_LOGINS_PER_SUBJECT` = 10 तक सीमित है, पर **असीमित `subject` की संख्या है** (`Mutex<HashMap>`, कोई बैकग्राउंड थ्रेड नहीं, प्रविष्टियाँ केवल बढ़ती हैं)। दीर्घकालिक प्रक्रियाओं को `ttl_secs` की कोटि के अंतराल पर `purge_expired` नियमित रूप से कॉल करना चाहिए। निष्क्रिय `subject` का इतिहास वापस लेने की कीमत यह है कि उसके अगले लॉगिन पर भिन्न-स्थान / असंभव-यात्रा की एक जाँच छूट जाती है — यह चूक है, फ़ॉल्स-पॉज़िटिव नहीं, और इतिहास तुरंत फिर बन जाता है

### `throttle` — दर सीमित करना

```rust
use security_rust::throttle::{MemoryThrottleStore, Throttle, ThrottleConfig, ThrottleDecision, ThrottleOutcome};

let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());

let key = "acct:user-42";
let now = 1_700_000_000u64;

match throttle.check(key, now) {
    ThrottleDecision::Allow { remaining } => { /* अनुमति */ }
    ThrottleDecision::Banned { until } => { /* प्रतिबंधित */ }
    ThrottleDecision::Unavailable => { /* स्टोर उपलब्ध नहीं */ }
}
// एक साथ कई आयाम जाँचें (जैसे IP + खाता): सबसे सख़्त नतीजा मान्य होता है
let merged = throttle.check_any(&["ip:203.0.113.7", "acct:user-42"], now);  // ThrottleDecision
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
use security_rust::{assess, Scanner};

// मज़बूत संकेत वाला पेलोड इस्तेमाल करें: टैग का केवल मौजूद होना कमज़ोर संकेत है (Low, 5 अंक)
let results = Scanner::default().scan("<img src=x onerror=alert(1)>");
let a = assess(&results);
println!("{} {}", a.level, a.score);   // CRITICAL 100

let a = Scanner::default().assess("<img src=x onerror=alert(1)>");  // सीधे RiskAssessment
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
| मास्कॉट | `src/pet.rs` | — |

## ज्ञात सीमाएँ

नीचे दी गई बातें **ज्ञात और जानबूझकर बनाए रखी गई** सीमाएँ हैं, ठीक होने की प्रतीक्षा में पड़े दोष नहीं। बदलाव से पहले आधार पढ़ें — हर सीमा माप से निकली है, और हर एक को कसने की कोशिश की जा चुकी है और हर बार वही दीवार मिली है।

### `dns_rebinding` केवल रिपोर्ट करता है, रोकता नहीं

कसौटी है «`Host:` हेडर में इंट्रानेट पता दिखना», और वही आकार k8s में हर pod-to-pod कॉल (`Host: 10.244.1.5:8080`), हर स्थानीय डेवलपमेंट (`Host: localhost:8000`) और Docker कंटेनर-नेटवर्क का हर अनुरोध (`172.18.0.2`) भी है। असली रीबाइंडिंग «सार्वजनिक डोमेन + भीतर की ओर इंगित रिज़ॉल्यूशन परिणाम» है, और ब्राउज़र जो `Host` भेजता है वह ठीक वही सार्वजनिक नाम है — **एक अकेली स्ट्रिंग में रिज़ॉल्यूशन का इतिहास दिखता ही नहीं**, इसलिए यह डिटेक्टर जिस आकार को नापता है वह हमले के आकार से मेल नहीं खाता, और इसे कसने की कोई दिशा नहीं है। इसलिए यह पूरा डिटेक्टर कमज़ोर स्तर का है और सदैव `Low` रिपोर्ट करता है; कितनी भी हिट जुड़ें, वह अकेले अस्वीकृति-रेखा पार नहीं करेगा। सुरक्षा रिज़ॉल्यूशन के **बाद** परिणामी IP की तुलना में है, स्ट्रिंग-स्तर पर नहीं।

### यह लाइब्रेरी अपने ही स्रोत, टेस्ट और दस्तावेज़ स्कैन नहीं कर सकती

सिग्नेचर स्कैनर की ऊपरी सीमा: इस रिपॉज़िटरी में मापे गए 298 में से 78 फ़ाइलें अस्वीकृति-रेखा पार करती हैं, और वे **बनावट से ही** हमले वाली स्ट्रिंग रखती हैं — टेस्ट पेलोड, डिटेक्टर स्रोत के अपने रेगेक्स लिटरल, तथा README और OWASP की तालिकाएँ जो इन पैटर्नों को गिनाती हैं। कोई README केवल `(a+)+` लिख देने से दोषपूर्ण नहीं हो जाता। अपने ही उत्पाद स्कैन करने हैं तो पहले इस कॉर्पस को बाहर रखना होगा, या कोई और कसौटी चुननी होगी।

### `upload` हर जगह `<%@` / `<?php` को Critical रिपोर्ट करता है

इस डिटेक्टर का अनुबंध है «**यह blob सर्वर पर चलने योग्य कोड है**» — दिखना ही पर्याप्त है, इसलिए यहाँ स्तरों का विभाजन नहीं है। JSP पेज और JSP webshell की प्रस्तावना बाइट-दर-बाइट एक ही होती है (`<%@ page language="java" … %>` और `<%@ page import="java.io.*" %>` एक ही आकार हैं), और `<%@`/`<%=` को कमज़ोर स्तर पर डालने का अर्थ है webshell को अस्वीकृति-रेखा के नीचे गिरा देना — यानी डिटेक्टर को दूसरे नाम से मिटा देना। कीमत यह है कि **अभी परोसे जा रहे** पेज (अपलोड की गई फ़ाइल के बजाय) को स्कैन करने पर भी हिट लगती है; वह इनपुट-क्षेत्र का मेल न होना है।

### `path_traversal` `(?:\.\./){2,}` को Critical रिपोर्ट करता है

मोनोरेपो में गहरे सापेक्ष पथ (`from '../../../shared/domain'`) हिट करते हैं। इसे और कसा नहीं गया, क्योंकि हमले से इसे अलग करने वाली एकमात्र शर्त लक्ष्य-फ़ाइल नामों की सूची है (`../etc/passwd` जैसी), और वह केवल सिस्टम फ़ाइलें कवर करती है — हमलावर दूसरा LFI लक्ष्य चुनकर बच निकलता है।

## प्रदर्शन

Release बिल्ड में, प्रत्येक डिटेक्टर अपने पैटर्न `static PATTERNS: LazyLock<Vec<Regex>>` स्थिर तालिका में रखता है, इसलिए हर regex प्रोसेस के भीतर पहले उपयोग पर एक ही बार कंपाइल होता है और आगे हर कॉल में दोबारा उपयोग होता है, जिसके बाद कोई कंपाइल लागत नहीं रहती। सभी 32 डिटेक्टरों का पूर्ण स्कैन कुछ दसियों माइक्रोसेकंड का होता है, और यह लागत डिटेक्टरों की संख्या तथा इनपुट लंबाई के साथ बढ़ती है; वास्तविक मान अपने हार्डवेयर और लोड पर मापें। उच्च थ्रूपुट परिदृश्यों (API गेटवे, लॉग पाइपलाइन) के लिए उपयुक्त।
