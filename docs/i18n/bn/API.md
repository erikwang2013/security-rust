<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust API রেফারেন্স

[中文](../../../README.md) | [English](../en/API.md) | [한국어](../ko/API.md) | [Русский](../ru/API.md) | [Deutsch](../de/API.md) | [Français](../fr/API.md) | [Español](../es/API.md) | [Português](../pt/API.md) | [हिन्दी](../hi/API.md) | [العربية](../ar/API.md) | [Bahasa Indonesia](../id/API.md) | [日本語](../ja/API.md) | [বাংলা (本页)](./API.md)

---

## কোর Trait

### `Detector`

সব ডিটেক্টরের একমাত্র চুক্তি:

```rust
pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
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

## দুই স্তরের সংকেত: শক্তিশালী ও দুর্বল

৩২টি ডিটেক্টরের ১৮টি তাদের প্যাটার্নকে দুই স্তরে ভাগ করে (প্রতিটি ডিটেক্টরের নিজস্ব শক্তিশালী/দুর্বল প্যাটার্ন সেট — বেশিরভাগই সেগুলো স্ট্যাটিকে রাখে, কিন্তু যেখানে শক্তিশালী শাখাটি শর্তসাপেক্ষ, যেমন `hpp` ও `cors`, সেখানে ইনলাইনে গড়া হয়)। `DetectionResult`-এর গঠন অপরিবর্তিত — বদলায় কেবল `severity`-র মান:

| স্তর | পরীক্ষা | `severity` | একটি একক হিট কি প্রত্যাখ্যান-রেখা ছাড়াতে পারে? |
|------|------|-----------|----------------------------------------|
| **শক্তিশালী** | আকৃতিটি নিজেই কেবল আক্রমণ থেকেই আসতে পারে | ডিটেক্টরের ঘোষিত গুরুতরতা | পারে |
| **দুর্বল** | টোকেনটির কেবল *উপস্থিতি* — সাধারণ কনটেন্টে তা সর্বত্র | সর্বদা `Severity::Low` (৫ পয়েন্ট) | **পারে না** |

একই ডিটেক্টর, একই `attack_type`, কেবল `severity` আলাদা। `detect()` আগে শক্তিশালী স্তর চেষ্টা করে, ব্যর্থ হলে দুর্বলে নামে, তাই **প্রতিটি ডিটেক্টর সর্বাধিক একটি ফলাফল ফেরত দেয়**। দুর্বল সংকেতও শনাক্ত হয় — কিছুই নীরবে বাদ পড়ে না।

`DetectionResult`-এ কোনো স্তর-ক্ষেত্র নেই — দুটিকে আলাদা করতে `severity == Severity::Low` দেখুন, `Low` কেবল এই একই উৎস থেকেই আসে। রেফারেন্স পাইপলাইন ৪০ পয়েন্টে প্রত্যাখ্যান করে (`risk.level >= RiskLevel::High`, [`examples/waf.rs:166`](../../../examples/waf.rs)); একটি দুর্বল সংকেতের মূল্য ৫, তাই সেটি ওই শাখায় পৌঁছাতে পারে না।

দুর্বল সংকেতের পেছনের আক্রমণ দেখতে `assess()`-ই কাজে লাগে:

```rust
let scanner = Scanner::default();

// তিনটি ভিন্ন ডিটেক্টর থেকে তিনটি দুর্বল সংকেত — স্তূপ করেও কেবল Medium
let a = scanner.assess("<script src=\"/app.js\"></script>\n../config\n__proto__");
assert_eq!(a.results, 3);
assert_eq!(a.score, 15);
assert_eq!(a.level, RiskLevel::Medium);
```

দুর্বল স্তরে নামানো প্যাটার্নের মধ্যে আছে `<script src=...>`, এক-স্তরের `../`, লাইন-শুরুর `-2`, খালি `__proto__`, `${env:}`, `X-Forwarded-Host`, `Host: localhost`, খালি `10.0.0.5`, `//evil.com`, এবং `information_schema` (পূর্ণ তালিকা প্রতিটি ডিটেক্টরের দুর্বল স্তরে)।

পরীক্ষাটি **আকৃতির**, ফাইলের নামের নয়: একই `../`-এর জন্য এক স্তর (`../x`) `Low` রিপোর্ট করে, বহু স্তর (`../../`) `Critical` ([`src/file/path_traversal.rs`](../../../src/file/path_traversal.rs))। প্রতি-ডিটেক্টরের সিলিং [README](./README.md)-এর ফিচার টেবিলে আছে।

## Scanner

### ইনস্টলেশন

```toml
[dependencies]
security-rust = "3.0.0"
```

### দ্রুত শুরু

```rust
use security_rust::Scanner;

fn main() {
    // শূন্য কনফিগারেশন: সব ৩২টি ডিটেক্টর একত্রিত হয়
    let scanner = Scanner::default();

    // ইনপুট স্ক্যান করে, সব শনাক্ত হওয়া আক্রমণ ফেরত দেয় (প্রতিটি ডিটেক্টর সর্বাধিক একটি)
    let results = scanner.scan("<img src=x onerror=alert(1)>");

    for r in &results {
        println!("[{}] {} — offset: {}, pattern: {}",
            r.severity, r.message, r.offset, r.matched_pattern);
    }
    // আউটপুট:
    // [CRITICAL] XSS cross-site scripting detected — offset: 11, pattern: onerror=

    // দুর্বল সংকেত একই ডিটেক্টর ও একই attack_type ব্যবহার করে, কিন্তু Low রিপোর্ট করে
    let weak = scanner.scan("<script src=\"/app.js\"></script>");
    // [LOW] XSS tag present (weak signal) — offset: 0, pattern: <script>
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

- `RequestContext` ক্ষেত্র: `token`, `subject`, `fingerprint`, `location`, `coords`, `signature`, `at`
- `SessionVerdict` ক্ষেত্র: `decision`, `severity: Option<Severity>` (অনুমোদন হলে `None`), `threats`
- `subject` **শুধু `bind` ব্যবহার করে, `verify` এটিকে সম্পূর্ণ উপেক্ষা করে**: প্রতি অনুরোধের পরিচয় সবসময় সার্ভারের `SessionRecord` থেকে নেওয়া হয় (ভিন্ন-স্থানের ইতিহাস `record.subject`-এ জমা হয়), আর অনুরোধকারীর পাঠানো `subject` অবিশ্বাসযোগ্য; তাই মিডলওয়্যার থেকে `subject: ""` পাঠানো বৈধ (`bind`-ই অখালি মান দাবি করে)। ঠিক এ কারণেই **কখনও** অনুরোধ হেডার থেকে নেওয়া ব্যবহারকারী-পরিচয় এখানে বসানো উচিত নয় — আজ তা সিদ্ধান্তে পৌঁছায় না, কিন্তু ভবিষ্যতের রিফ্যাক্টর তা বজায় রাখতে বাধ্য নয়।
- `Decision`: `Allow` | `Challenge` | `Block`
- স্টোর unavailable হলে ফলাফল `Decision::Block` (কারণ `StoreUnavailable`) — অর্থাৎ **fail-closed**, কোনো পথ খোলা থাকে না
- `SessionConfig` ডিফল্ট: `ttl_secs` = 3600, `impossible_travel_kmh` = 900.0, `timestamp_skew_secs` = 300
- স্টোর trait `SessionStore` দিয়ে বিমূর্ত, প্রস্তুত বাস্তবায়ন `MemoryStore`; মাল্টি-ইনস্ট্যান্স ডিপ্লয়ের জন্য এই trait Redis-এর জন্য বাস্তবায়ন করুন
- `purge_expired(now)` মেয়াদোত্তীর্ণ এন্ট্রি ছাড়ায়: `expires_at <= now` হওয়া সেশন, আর যে subject-এর `now - LOGIN_HISTORY_KEEP_SECS` (৭ দিন)-এর পরে কোনো লগইন নেই তার সম্পূর্ণ লগইন ইতিহাস। দীর্ঘকাল চলা প্রসেসে এটি `ttl_secs`-এর ক্রমের ব্যবধানে টাইমারে ডাকুন। **ফেরত মান কেবল সেশন গোনে**, রিসাইকেল করা লগইন ইতিহাস কখনো নয়। কোনো সুপ্ত subject-এর ইতিহাস ফিরে পেতে হলে পরের লগইনে তার একবার ভিন্ন-স্থান / impossible-travel পরীক্ষা বাদ পড়ে (এরপর ইতিহাস আবার গড়ে ওঠে) — এটি false negative, false positive নয়
- **subject-এর সংখ্যা অসীম।** `MemoryStore` প্রতিটি subject-এর লগইন ইতিহাস `MAX_LOGINS_PER_SUBJECT` = 10-এ সীমাবদ্ধ রাখে, কিন্তু কতজন subject থাকবে তা কিছুই সীমাবদ্ধ করে না (`Mutex<HashMap>`, কোনো background thread নেই, এন্ট্রি কেবল বাড়তেই থাকে)

### `throttle` — রেট সীমা

```rust
use security_rust::throttle::{MemoryThrottleStore, Throttle, ThrottleConfig, ThrottleDecision, ThrottleOutcome};

let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());

let key = "acct:user-42";
let now = 1_700_000_000u64;

match throttle.check(key, now) {
    ThrottleDecision::Allow { remaining } => { /* অনুমোদিত */ }
    ThrottleDecision::Banned { until } => { /* নিষিদ্ধ */ }
    ThrottleDecision::Unavailable => { /* স্টোর unavailable */ }
}
// একসাথে একাধিক মাত্রা পরীক্ষা (যেমন IP + অ্যাকাউন্ট): সবচেয়ে কঠোর ফলটিই গৃহীত হয়
let merged = throttle.check_any(&["ip:203.0.113.7", "acct:user-42"], now);  // ThrottleDecision
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
use security_rust::{assess, Scanner};

// শক্তিশালী-সংকেত পেলোড ব্যবহার করুন: ট্যাগের কেবল *উপস্থিতি* হলো দুর্বল সংকেত (Low, ৫ পয়েন্ট)
let results = Scanner::default().scan("<img src=x onerror=alert(1)>");
let a = assess(&results);
println!("{} {}", a.level, a.score);   // CRITICAL 100

let a = Scanner::default().assess("<img src=x onerror=alert(1)>");  // সরাসরি RiskAssessment
```

- `RiskLevel`: `None` | `Low` | `Medium` | `High` | `Critical`
- `RiskAssessment` ক্ষেত্র: `level`, `score`, `results` (সমবেত হওয়া হিটের সংখ্যা)
- ওজন: Critical = 100, High = 40, Medium = 15, Low = 5
- খালি ফলাফল-সেট ⇒ `None`; যেকোনো `Severity::Critical` ⇒ সরাসরি `Critical` (শর্ট-সার্কিট, জমা হওয়ার দরকার নেই); নাহলে মোট অনুযায়ী ব্যান্ড: `1..=14` → Low, `15..=39` → Medium, `40..=99` → High, `≥100` → Critical — অর্থাৎ ৩ × Low (১৫ পয়েন্ট) Medium-এ ওঠে, আর ৮ × Low (৪০ পয়েন্ট) High-এ ওঠে
- **এটিই দুর্বল সংকেতের একমাত্র উত্তরণ-পথ** — একটি দুর্বল সংকেতের মূল্য ৫ পয়েন্ট, একা ৪০-পয়েন্ট প্রত্যাখ্যান-রেখা কখনো ছাড়াতে পারে না; কেবল ভিন্ন ভিন্ন ডিটেক্টর থেকে আসা কয়েকটি একসাথে স্তূপ হলে পারে। তাই একটি রিকোয়েস্টের প্রতিটি মাত্রা একই `Scanner`-এ ঢাললে দুর্বল সংকেতের পেছনের আক্রমণ অনেক বেশি প্রকাশ পায়; উল্টোদিকে একটি ছোট ফিল্ড স্ক্যান করলে দুর্বল-সংকেত নিয়ে ভাবতেই হয় না
- মনে রাখুন `Severity`-তে **`Ord` নেই** (ঘোষণার ক্রম Critical → Low, অবরোহী, তাই `Ord` derive করলে `max()` নীরবে সবচেয়ে হালকা হিটটিই বেছে নিত); ওজন-টেবিল থাকে স্কোরিংয়ের দিকে। `RiskLevel` ঠিক উল্টো: তার ঘোষণার ক্রমই শক্তির ক্রম

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
| পেট | `src/pet.rs` | — |

## জ্ঞাত সীমাবদ্ধতা

নিচের সীমাগুলো **জ্ঞাত ও সচেতনভাবে রাখা** সীমানা, সারানোর অপেক্ষায় থাকা ত্রুটি নয়। প্রতিটির পেছনে মাপা প্রমাণ আছে, আর প্রতিটি ইতিমধ্যেই এটিকে আরও কঠোর করার একেকটি প্রচেষ্টাকে হারিয়ে দিয়েছে।

### `dns_rebinding` রিপোর্ট করে, আটকায় না

এর পরীক্ষা "`Host:`-এ একটি ইন্টারনাল ঠিকানা আছে" — আর এই একই আকৃতি হলো প্রতিটি k8s পড-টু-পড কল (`Host: 10.244.1.5:8080`), প্রতিটি লোকাল ডেভেলপমেন্ট রিকোয়েস্ট (`Host: localhost:8000`), এবং প্রতিটি Docker কন্টেইনার-নেটওয়ার্ক কল (`172.18.0.2`)। প্রকৃত রিবাইন্ডিং হলো "একটি পাবলিক ডোমেইন নাম + ভেতরের দিকে নির্দেশ করা রেজোলিউশন ফলাফল", আর ব্রাউজার যে `Host` পাঠায় সেটি ঠিক সেই পাবলিক নামটিই — **একটি একক স্ট্রিং কোনো রেজোলিউশন ইতিহাস বহন করে না**, তাই এই ডিটেক্টর যে আকৃতি পরীক্ষা করে তা আক্রমণের আকৃতির সাথে ওভারল্যাপ করে না, আর কঠোর করার কোনো উপায়ও নেই। ডিটেক্টরটি সম্পূর্ণই দুর্বল স্তরের এবং সর্বদা `Low` রিপোর্ট করে; কতবার স্তূপ করলেও এটি একা প্রত্যাখ্যান-রেখা ছাড়াতে পারে না। সুরক্ষা রেজোলিউশনের পরে, পাওয়া IP তুলনা করে দেওয়া উচিত — স্ট্রিং স্তরে নয়।

### এই ক্রেট নিজের সোর্স, টেস্ট বা ডক স্ক্যান করতে পারে না

সিগনেচার স্ক্যানারের সিলিং: এই রিপোজিটরিতে মাপা গেছে, ২৯৮টি ফাইলের মধ্যে ৭৮টি প্রত্যাখ্যান-রেখা ছাড়ায়, আর প্রত্যেকটিতে আক্রমণ-স্ট্রিং আছে **গঠনগতভাবেই** — টেস্ট পেলোড, ডিটেক্টর সোর্সের নিজের রেজেক্স লিটারাল, আর README/OWASP টেবিল যা প্যাটার্নগুলোর নাম করে। `(a+)+` তালিকাভুক্ত করায় একটি README ত্রুটিপূর্ণ হয়ে যায় না। নিজের আর্টিফ্যাক্ট স্ক্যান করতে হলে আগে সেই কর্পাস বাদ দিতে হবে, নইলে ভিন্ন পরীক্ষা বেছে নিতে হবে।

### `upload` সর্বত্র `<%@` / `<?php`-কে Critical হিসেবে রিপোর্ট করে

ডিটেক্টরের চুক্তি হলো "**এই ব্লবটি সার্ভার-পাশে চালনাযোগ্য কোড**" — কেবল উপস্থিতিই তা প্রতিষ্ঠা করে, তাই এখানে কোনো স্তর-বিভাজন নেই। একটি JSP পেজ আর একটি JSP ওয়েবশেল তাদের সূচনা অংশ বাইট ধরে ধরে ভাগ করে (`<%@ page language="java" … %>` আর `<%@ page import="java.io.*" %>` একই আকৃতি); `<%@`/`<%=`-কে নামিয়ে দিলে ওয়েবশেল শনাক্তকরণ প্রত্যাখ্যান-রেখার নিচে চলে যেত — সেটি অন্য নামে মুছে ফেলা মাত্র। খরচটি হলো: **বর্তমানে পরিবেশিত** একটি পেজ স্ক্যান করলেও (আপলোড করা ফাইলের বদলে) সেটি ধরা পড়ে; এটি ইনপুট-ডোমেইনের অসঙ্গতি।

### `path_traversal` `(?:\.\./){2,}`-কে Critical হিসেবে রিপোর্ট করে

মনোরেপোতে থাকা গভীর আপেক্ষিক পাথ (`from '../../../shared/domain'`) মিলে যায়। এটিকে আরও কঠোর করা হয়নি, কারণ আক্রমণ থেকে এটিকে আলাদা করা একমাত্র শর্ত হলো লক্ষ্য-নামের তালিকা (`../etc/passwd` প্রভৃতি), যা কেবল সিস্টেম ফাইল কভার করে — আক্রমণকারী কেবল অন্য একটি LFI লক্ষ্য বেছে নেয়।

## পারফরম্যান্স

Release বিল্ডে, প্রতিটি ডিটেক্টর তার প্যাটার্নগুলো `static PATTERNS: LazyLock<Vec<Regex>>` স্ট্যাটিক টেবিলে রাখে, ফলে প্রতিটি regex প্রসেসের ভেতরে প্রথম ব্যবহারে একবারই কম্পাইল হয় এবং পরবর্তী প্রতিটি কলে পুনরায় ব্যবহৃত হয়, এরপর আর কোনো কম্পাইল খরচ থাকে না। সম্পূর্ণ ৩২টি ডিটেক্টরের স্ক্যান কয়েক ডজন মাইক্রোসেকেন্ড সময় নেয়, এবং এই খরচ ডিটেক্টরের সংখ্যা ও ইনপুট দৈর্ঘ্যের সাথে বাড়ে; প্রকৃত মান নিজের হার্ডওয়্যার ও লোডে মেপে নিন। উচ্চ থ্রুপুট পরিস্থিতির জন্য উপযুক্ত (API গেটওয়ে, লগ পাইপলাইন)।
