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

> `session` ও `throttle` ইচ্ছাকৃতভাবে এই trait প্রয়োগ করে না — তাদের ইনপুট মিশ্র (token + fingerprint + লোকেশন + সময়), যা `Detector::detect(&str)` প্রকাশ করতে পারে না। নিচে «স্টেটফুল মডিউল ও ঝুঁকি স্কোরিং» দেখুন।

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
security-rust = "1.1.0"
```

### দ্রুত শুরু

```rust
use security_rust::Scanner;

fn main() {
    // শূন্য কনফিগারেশন: সব ৩২টি ডিটেক্টর একত্রিত হয়
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

বাকি স্টেট লেবেলগুলিও `Display` প্রয়োগ করে এবং বড় হাতের অক্ষরে ছাপে: `Decision` (`ALLOW` / `CHALLENGE` / `BLOCK`), `SessionThreat` (যেমন `impossible travel (11205 km/h)`), `AttackCategory` (ছোট হাতের, যেমন `injection`), `ThrottleDecision` (`ALLOW` / `BANNED` / `UNAVAILABLE`), `ThrottleOutcome` (`ALLOW` / `BANNED`)।

```rust
println!("{} {}", verdict.decision, verdict.threats.len());  // BLOCK 2
```

## স্টেটফুল মডিউল ও ঝুঁকি স্কোরিং

এই তিনটি মডিউল সরাসরি ক্রেট রুট থেকে পাওয়া যায়। `session` ও `throttle` ইচ্ছাকৃতভাবে `Detector` trait প্রয়োগ করে না, কারণ তাদের ইনপুট মিশ্র। কোনো নতুন বাহ্যিক নির্ভরতা যোগ হয় না: token ও signature (MAC) কলার সরবরাহ করে, এবং লোকেশন পার্স করাও কলারের দায়িত্ব।

### `session` — সেশন নিরাপত্তা

```rust
use security_rust::session::{MemoryStore, RequestContext, SessionConfig, SessionGuard};

let guard = SessionGuard::new(MemoryStore::new(), SessionConfig::default());

let v = guard.bind(&ctx, now)?;        // Result<SessionVerdict, SessionError>
let v = guard.verify(&ctx, now);       // SessionVerdict
guard.revoke(token)?;                  // Result<(), StoreError>
let n = guard.revoke_all(subject)?;    // Result<usize, StoreError>
guard.rotate(old, new, &ctx, now)?;    // Result<(), SessionError>
```

- `RequestContext` ক্ষেত্র: `token`, `subject`, `fingerprint`, `location`, `coords`, `signature`, `at`
- `SessionVerdict` ক্ষেত্র: `decision`, `severity: Option<Severity>` (অনুমোদন হলে `None`), `threats`
- `subject` **শুধু `bind` ব্যবহার করে, `verify` এটিকে সম্পূর্ণ উপেক্ষা করে**: প্রতি অনুরোধের পরিচয় সবসময় সার্ভারের `SessionRecord` থেকে নেওয়া হয় (ভিন্ন-স্থানের ইতিহাস `record.subject`-এ জমা হয়), আর অনুরোধকারীর পাঠানো `subject` অবিশ্বাসযোগ্য; তাই মিডলওয়্যার থেকে `subject: ""` পাঠানো বৈধ (`bind`-ই অখালি মান দাবি করে)। ঠিক এ কারণেই **কখনও** অনুরোধ হেডার থেকে নেওয়া ব্যবহারকারী-পরিচয় এখানে বসানো উচিত নয় — আজ তা সিদ্ধান্তে পৌঁছায় না, কিন্তু ভবিষ্যতের রিফ্যাক্টর তা বজায় রাখতে বাধ্য নয়।
- `Decision`: `Allow` | `Challenge` | `Block`
- স্টোর unavailable হলে ফলাফল `Decision::Block` (কারণ `StoreUnavailable`) — অর্থাৎ **fail-closed**, কোনো পথ খোলা থাকে না
- `SessionConfig` ডিফল্ট: `ttl_secs` = 3600, `impossible_travel_kmh` = 900.0, `timestamp_skew_secs` = 300
- স্টোর trait `SessionStore` দিয়ে বিমূর্ত, প্রস্তুত বাস্তবায়ন `MemoryStore`; মাল্টি-ইনস্ট্যান্স ডিপ্লয়ের জন্য এই trait Redis-এর জন্য বাস্তবায়ন করুন

### `throttle` — রেট সীমা

```rust
use security_rust::throttle::{MemoryThrottleStore, Throttle, ThrottleConfig, ThrottleDecision, ThrottleOutcome};

let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());

match throttle.check(key, now) {
    ThrottleDecision::Allow { remaining } => { /* অনুমোদিত */ }
    ThrottleDecision::Banned { until } => { /* নিষিদ্ধ */ }
    ThrottleDecision::Unavailable => { /* স্টোর unavailable */ }
}
// একসাথে একাধিক মাত্রা পরীক্ষা (যেমন IP + অ্যাকাউন্ট): সবচেয়ে কঠোর ফলটিই গৃহীত হয়
let merged = throttle.check_any(&["ip:203.0.113.7", "user:42"], now);  // ThrottleDecision
let outcome = throttle.record_failure(key, now)?;  // Result<ThrottleOutcome, StoreError>
throttle.record_success(key)?;       // Result<(), StoreError>
throttle.reset(key)?;                // Result<(), StoreError>
throttle.purge_expired(now)?;        // Result<usize, StoreError>
```

- `ThrottleConfig` ডিফল্ট: `threshold` = 5, `window_secs` = 60, `ban_secs` = 900
- `check_any(&[key, ...], now)` একাধিক মাত্রা একত্র করে: কোনোটি `Banned` হলে সেটিই জেতে (সর্বাধিক দূরের `until`), নাহলে `Unavailable`, নাহলে ক্ষুদ্রতম `remaining`-সহ `Allow`; খালি তালিকা দিলে `Allow { remaining: 0 }`
- `ThrottleOutcome` (`Allow { remaining }` | `Banned { until }`) হলো `record_failure`-এর ফল; এতে `Unavailable` নেই, কারণ স্টোর ব্যর্থতা সেখানে `Err(StoreError)` হয়ে ফেরে
- **ইচ্ছাকৃত ব্যতিক্রম**: স্টোর ব্যর্থ হলে `check` / `check_any` `Banned` নয়, `Unavailable` ফেরত দেয় — রেট সীমা defense-in-depth, মূল প্রমাণীকরণের দরজা নয়; ব্যাকএন্ড গোলযোগে সব ব্যবহারকারীকে আটকানো নিজের বিরুদ্ধে DoS, আর সিদ্ধান্ত কলারের হাতে ছাড়া
- স্টোর trait `ThrottleStore` দিয়ে বিমূর্ত, প্রস্তুত বাস্তবায়ন `MemoryThrottleStore`

### `score` — ঝুঁকি স্কোরিং

```rust
use security_rust::assess;

let results = Scanner::default().scan(input);
let a = assess(&results);
println!("{} {}", a.level, a.score);   // উদাহরণ: HIGH 40

let a = Scanner::default().assess(input);  // সরাসরি RiskAssessment
```

- `RiskLevel`: `None` | `Low` | `Medium` | `High` | `Critical`
- `RiskAssessment` ক্ষেত্র: `level`, `score`, `results` (সমবেত হওয়া হিটের সংখ্যা)
- ওজন: Critical = 100, High = 40, Medium = 15, Low = 5

## মডিউল পাথ

| মডিউল | পাথ | ডিটেক্টর সংখ্যা |
|------|------|---------|
| কোর | `src/lib.rs` `result.rs` `scanner.rs` | — |
| ইনজেকশন | `src/injection/` | 11 |
| প্রোটোকল | `src/protocol/` | 11 |
| ডেটা | `src/data/` | 7 |
| ফাইল | `src/file/` | 3 |
| সেশন | `src/session/` | — |
| রেট সীমা | `src/throttle/` | — |
| ঝুঁকি স্কোরিং | `src/score.rs` | — |

## পারফরম্যান্স

Release বিল্ডে, প্রতিটি ডিটেক্টর তার প্যাটার্নগুলো `static PATTERNS: LazyLock<Vec<Regex>>` স্ট্যাটিক টেবিলে রাখে, ফলে প্রতিটি regex প্রসেসের ভেতরে প্রথম ব্যবহারে একবারই কম্পাইল হয় এবং পরবর্তী প্রতিটি কলে পুনরায় ব্যবহৃত হয়, এরপর আর কোনো কম্পাইল খরচ থাকে না। সম্পূর্ণ ৩২টি ডিটেক্টরের স্ক্যান কয়েক ডজন মাইক্রোসেকেন্ড সময় নেয়, এবং এই খরচ ডিটেক্টরের সংখ্যা ও ইনপুট দৈর্ঘ্যের সাথে বাড়ে; প্রকৃত মান নিজের হার্ডওয়্যার ও লোডে মেপে নিন। উচ্চ থ্রুপুট পরিস্থিতির জন্য উপযুক্ত (API গেটওয়ে, লগ পাইপলাইন)।
