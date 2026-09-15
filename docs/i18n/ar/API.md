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

> لا تنفّذ `session` و`throttle` هذا الـ trait عمدًا — مدخلاتهما مركّبة (توكن + بصمة + موقع + وقت) ولا يعبّر عنها `Detector::detect(&str)`. راجع قسم «الوحدات ذات الحالة وتقييم المخاطر» أدناه.

## بنية نتيجة الكشف

```rust
pub struct DetectionResult {
    pub attack_type: String,      // "xss", "sql_injection" ...
    pub category: AttackCategory, // Injection | Protocol | Data | File
    pub severity: Severity,       // Critical | High | Medium | Low
    pub matched_pattern: String,  // الجزء المطابق من النمط
    pub offset: usize,            // إزاحة البايت في المدخل
    pub message: String,          // وصف مقروء للبشر
}
```

## Scanner

### التثبيت

```toml
[dependencies]
security-rust = "1.0.8"
```

### بداية سريعة

```rust
use security_rust::Scanner;

fn main() {
    // بدون إعداد: تجميع الكاشفات الـ 32 كلها
    let scanner = Scanner::default();

    // فحص المدخل وإعادة كل الهجمات المكتشفة
    let results = scanner.scan("<script>alert('xss')</script>");

    for r in &results {
        println!("[{}] {} — offset: {}, pattern: {}",
            r.severity, r.message, r.offset, r.matched_pattern);
    }
    // الناتج:
    // [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
}
```

### الفحص الانتقائي

```rust
let scanner = Scanner::default();

// تشغيل الكاشفات المحددة فقط
let results = scanner.scan_with(
    "1 UNION SELECT password FROM users",
    &["sql_injection", "xss"],
);
```

### الإعدادات المخصصة

```rust
use security_rust::injection::{XssDetector, SqlInjectionDetector};

// تجميع الكاشفات المطلوبة فقط عبر builder
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

## الوحدات ذات الحالة وتقييم المخاطر

هذه الوحدات الثلاث متاحة مباشرة من جذر المكتبة. لا تنفّذ `session` و`throttle` الـ trait `Detector` لأن مدخلاتهما مركّبة. ولا تُضاف أي اعتمادية خارجية: التوكن والتوقيع (MAC) يوفّرهما المستدعي، وتحليل الموقع مسؤولية المستدعي أيضًا.

### `session` — أمان الجلسات

```rust
use security_rust::session::{MemoryStore, RequestContext, SessionConfig, SessionGuard};

let guard = SessionGuard::new(MemoryStore::new(), SessionConfig::default());

let v = guard.bind(&ctx, now)?;        // Result<SessionVerdict, SessionError>
let v = guard.verify(&ctx, now);       // SessionVerdict
guard.revoke(token)?;                  // Result<(), StoreError>
let n = guard.revoke_all(subject)?;    // Result<usize, StoreError>
guard.rotate(old, new, &ctx, now)?;    // Result<(), SessionError>
```

- حقول `RequestContext`: `token`، `subject`، `fingerprint`، `location`، `coords`، `signature`، `at`
- حقول `SessionVerdict`: `decision`، `severity`، `threats`
- `Decision`: `Allow` | `Challenge` | `Block`
- عند تعذّر الوصول إلى المخزن تكون النتيجة `Decision::Block` (والسبب `StoreUnavailable`) — أي **fail-closed**، ولا يوجد مسار يسمح بالمرور
- افتراضات `SessionConfig`: `ttl_secs` = 3600، و`impossible_travel_kmh` = 900.0، و`timestamp_skew_secs` = 300
- المخزن مجرّد عبر trait `SessionStore` والتنفيذ الجاهز `MemoryStore`؛ وللنشر على عدة نسخ نفّذ هذا الـ trait لـ Redis

### `throttle` — الحد من المعدل

```rust
use security_rust::throttle::{MemoryThrottleStore, Throttle, ThrottleConfig, ThrottleDecision};

let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());

match throttle.check(key, now) {
    ThrottleDecision::Allow { remaining } => { /* مسموح */ }
    ThrottleDecision::Banned { until } => { /* محظور */ }
    ThrottleDecision::Unavailable => { /* تعذّر الوصول إلى المخزن */ }
}
throttle.record_failure(key, now)?;  // Result<ThrottleDecision, StoreError>
throttle.record_success(key)?;       // Result<(), StoreError>
throttle.reset(key)?;                // Result<(), StoreError>
throttle.purge_expired(now)?;        // Result<usize, StoreError>
```

- افتراضات `ThrottleConfig`: `threshold` = 5، و`window_secs` = 60، و`ban_secs` = 900
- **استثناء مقصود**: عند تعطّل المخزن تُعيد `Unavailable` وليس `Banned` — الحد من المعدل دفاع في العمق وليس البوابة الأساسية للمصادقة، ومنع جميع المستخدمين بسبب خلل في الخلفية هو حجب للذات (self-DoS)، وقرار التصرف متروك للمستدعي
- المخزن مجرّد عبر trait `ThrottleStore` والتنفيذ الجاهز `MemoryThrottleStore`

### `score` — تقييم المخاطر

```rust
use security_rust::assess;

let results = Scanner::default().scan(input);
let a = assess(&results);
println!("{} {}", a.level, a.score);   // مثلاً: HIGH 40

let a = Scanner::default().assess(input);  // RiskAssessment مباشرة
```

- `RiskLevel`: `None` | `Low` | `Medium` | `High` | `Critical`
- حقول `RiskAssessment`: `level`، `score`، `results` (عدد النتائج المشاركة في التجميع)
- الأوزان: Critical = 100، وHigh = 40، وMedium = 15، وLow = 5

## مسارات الوحدات

| الوحدة | المسار | عدد الكاشفات |
|------|------|---------|
| النواة | `src/lib.rs` `result.rs` `scanner.rs` | — |
| الحقن | `src/injection/` | 11 |
| البروتوكول | `src/protocol/` | 11 |
| البيانات | `src/data/` | 7 |
| الملفات | `src/file/` | 3 |
| الجلسات | `src/session/` | — |
| الحد من المعدل | `src/throttle/` | — |
| تقييم المخاطر | `src/score.rs` | — |

## الأداء

مع بناء Release، يحتفظ كل كاشف بجدول ساكن من الأنماط `static PATTERNS: LazyLock<Vec<Regex>>`، فتُجمَّع كل تعبير منتظم مرة واحدة عند أول استخدام داخل العملية ثم يُعاد استخدامه في كل استدعاء لاحق دون أي تكلفة تجميع. وفحص جميع الكاشفات الـ 32 يقع في حدود عشرات الميكروثانية في المرة، ويزداد مع عدد الكاشفات وطول المدخل؛ لذا يُستحسن القياس على العتاد والحمل الفعليين. مناسب لسيناريوهات الإنتاجية العالية (بوابات API وخطوط أنابيب السجلات).
