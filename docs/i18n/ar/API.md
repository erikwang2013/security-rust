<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# مرجع API لـ security-rust

[中文](../../../README.md) | [English](../en/API.md) | [한국어](../ko/API.md) | [Русский](../ru/API.md) | [Deutsch](../de/API.md) | [Français](../fr/API.md) | [Español](../es/API.md) | [Português](../pt/API.md) | [हिन्दी](../hi/API.md) | [বাংলা](../bn/API.md) | [Bahasa Indonesia](../id/API.md) | [日本語](../ja/API.md) | [العربية (本页)](./API.md)

---

## Trait الأساسي

### `Detector`

العقد الوحيد لجميع الكاشفات:

```rust
pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
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

## مستويان من الإشارات: قوية وضعيفة

تقسّم 18 من بين الكاشفات الـ 32 أنماطها إلى مستويين (الجدولان الثابتان `STRONG_PATTERNS` / `WEAK_PATTERNS` في الشيفرة المصدرية). وبنية حقول `DetectionResult` لم تتغير — الذي تغيّر هو قيمة `severity`:

| المستوى | المعيار | `severity` | هل تكفي إصابة واحدة لتجاوز حد الرفض |
|------|------|-----------|------------------|
| **إشارة قوية** | الشكل نفسه لا يصدر إلا عن هجوم | المستوى المعلن للكاشف | نعم |
| **إشارة ضعيفة** | مجرّد «ظهور» الرمز — وهو منتشر في المحتوى العادي | `Severity::Low` دائمًا (5 نقاط) | **لا** |

الكاشف نفسه، و`attack_type` نفسه، ولا يختلف إلا `severity`؛ ويجرّب `detect()` المستوى القوي أولًا ثم يعود إلى الضعيف، لذلك **لا يُعيد كل كاشف أكثر من نتيجة واحدة**. والإشارات الضعيفة تُكتشف مع ذلك ولا تُهمَل بصمت.

و`DetectionResult` نفسه لا يفرّق بين المستويين — ولمعرفة ما إذا كانت الإصابة قوية أم ضعيفة يكفي فحص `severity == Severity::Low` (فالمستوى الضعيف هو المصدر الوحيد الذي يُبلّغ بـ`Low`). وحدّ الرفض في خط المعالجة المرجعي هو 40 نقطة (`risk.level >= RiskLevel::High`، انظر [`examples/waf.rs:166`](../../../examples/waf.rs))؛ والإشارة الضعيفة الواحدة تساوي 5 نقاط فلا تبلغ هذا الفرع.

وأداة رؤية الهجوم خلف الإشارات الضعيفة هي `assess()`، التي تجمع إصابات عدة كاشفات؛ وهذا **هو مسار الارتفاع الوحيد للإشارة الضعيفة** — فـ 5 نقاط لا تتجاوز حدّ 40 أبدًا، وإنما يفعله تراكم عدة إصابات (من كاشفات مختلفة). ولذلك فإن تمرير مدخلات كل الأبعاد إلى `Scanner` واحد أكشف للهجوم خلف الإشارات الضعيفة من فحص حقل واحد؛ وبالمقابل، عند فحص حقل واحد قصير لا يلزم اتخاذ أي إجراء بشأن الإشارات الضعيفة.

```rust
let scanner = Scanner::default();

// ثلاث إشارات ضعيفة أصابت ثلاثة كاشفات مختلفة: التراكم وحده يبلغ Medium (15 نقطة)، ولا يبلغ High
let a = scanner.assess("<script src=\"/app.js\"></script>\n../config\n__proto__");
assert_eq!(a.results, 3);
assert_eq!(a.score, 15);
assert_eq!(a.level, RiskLevel::Medium);
```

ومن أمثلة الأشكال التي خُفِّضت إلى المستوى الضعيف (القائمة الكاملة في `WEAK_PATTERNS` لكل كاشف): `<script src=...>`، و`../` بمستوى واحد، و`-2` في بداية السطر، و`__proto__` مجرّدًا، و`${env:}`، و`X-Forwarded-Host`، و`Host: localhost`، و`10.0.0.5` مجرّدًا، و`//evil.com`، و`information_schema`.

والمعيار هو **الشكل** لا اسم الملف: فبالنسبة إلى `../` نفسه، المستوى الواحد (`../x`) يُبلَّغ بـ`Low`، وتعدّد المستويات (`../../`) بـ`Critical` ([`src/file/path_traversal.rs`](../../../src/file/path_traversal.rs)). وأقصى ما يبلغه كل كاشف تجده في الجداول أدناه وفي جداول الميزات في [README](./README.md).

## Scanner

### التثبيت

```toml
[dependencies]
security-rust = "3.0.0"
```

### بداية سريعة

```rust
use security_rust::Scanner;

fn main() {
    // بدون إعداد: تجميع الكاشفات الـ 32 كلها
    let scanner = Scanner::default();

    // فحص المدخل وإعادة كل الهجمات المكتشفة (نتيجة واحدة على الأكثر لكل كاشف)
    let results = scanner.scan("<img src=x onerror=alert(1)>");

    for r in &results {
        println!("[{}] {} — offset: {}, pattern: {}",
            r.severity, r.message, r.offset, r.matched_pattern);
    }
    // الناتج:
    // [CRITICAL] XSS cross-site scripting detected — offset: 11, pattern: onerror=

    // الإشارة الضعيفة تمر عبر الكاشف نفسه وعبر attack_type نفسه، ولا يختلف إلا severity = Low
    let weak = scanner.scan("<script src=\"/app.js\"></script>");
    // [LOW] XSS tag present (weak signal) — offset: 0, pattern: <script>
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

بقية وسوم الحالة تُنفّذ `Display` أيضًا وتُطبع بحروف كبيرة: `Decision` (`ALLOW` / `CHALLENGE` / `BLOCK`)، و`SessionThreat` (مثل `impossible travel (11205 km/h)`)، و`AttackCategory` (بحروف صغيرة، مثل `injection`)، و`ThrottleDecision` (`ALLOW` / `BANNED` / `UNAVAILABLE`)، و`ThrottleOutcome` (`ALLOW` / `BANNED`).

```rust
println!("{} {}", verdict.decision, verdict.threats.len());  // BLOCK 2
```

## الوحدات ذات الحالة وتقييم المخاطر

هذه الوحدات الثلاث متاحة مباشرة من جذر المكتبة. لا تنفّذ `session` و`throttle` الـ trait `Detector` لأن مدخلاتهما مركّبة. ولا تُضاف أي اعتمادية خارجية: التوكن والتوقيع (MAC) يوفّرهما المستدعي، وتحليل الموقع مسؤولية المستدعي أيضًا.

### `session` — أمان الجلسات

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

- حقول `RequestContext`: `token`، `subject`، `fingerprint`، `location`، `coords`، `signature`، `at`
- حقول `SessionVerdict`: `decision`، و`severity: Option<Severity>` (تكون `None` عند السماح)، و`threats`
- `subject` **يستخدمه `bind` فقط، و`verify` يتجاهله تمامًا**: هوية كل طلب تُؤخذ دائمًا من `SessionRecord` في الخادم (وسجل المواقع الغريبة يُجمَّع على `record.subject`)، وقيمة `subject` الواردة من الطالب غير موثوقة؛ ولذلك فإن `subject: ""` من الـ middleware قيمة صحيحة (`bind` هو الذي يطلب قيمة غير فارغة). ولهذا تحديدًا **لا يجوز إطلاقًا** وضع معرّف مستخدم مأخوذ من ترويسة الطلب هنا: فهو لا يصل إلى القرار اليوم، لكن إعادة الهيكلة مستقبلًا غير ملزمة بالحفاظ على ذلك.
- `Decision`: `Allow` | `Challenge` | `Block`
- عند تعذّر الوصول إلى المخزن تكون النتيجة `Decision::Block` (والسبب `StoreUnavailable`) — أي **fail-closed**، ولا يوجد مسار يسمح بالمرور
- افتراضات `SessionConfig`: `ttl_secs` = 3600، و`impossible_travel_kmh` = 900.0، و`timestamp_skew_secs` = 300
- المخزن مجرّد عبر trait `SessionStore` والتنفيذ الجاهز `MemoryStore`؛ وللنشر على عدة نسخ نفّذ هذا الـ trait لـ Redis
- `purge_expired(now)` يحذف الجلسات التي `expires_at <= now`، ويحذف سجل الدخول كاملًا لكل `subject` كانت آخر نقطة دخول له أقدم من `now - LOGIN_HISTORY_KEEP_SECS` (7 أيام). **والقيمة المُعادة تعدّ الجلسات فقط**، دون سجل الدخول المُستعاد
- **عدد الـ `subject` في `MemoryStore` غير محدود**: عدد سجلات الدخول لكل `subject` مقيّد بالثابت `MAX_LOGINS_PER_SUBJECT` = 10، أما عدد الـ `subject` نفسه فلا حدّ له (`Mutex<HashMap>`، بلا خيط خلفي، والمدخلات تزداد ولا تنقص). فعلى العمليات طويلة العمر أن تستدعي `purge_expired` دوريًا بفاصل من رتبة `ttl_secs`. واستعادة سجل `subject` خامل تُكلِّف أنه يتخطى في تسجيل دخوله التالي فحصًا واحدًا للموقع الغريب / السفر المستحيل — وهو تفويت لا إنذار كاذب، ويُعاد بناء السجل فورًا بعدها

### `throttle` — الحد من المعدل

```rust
use security_rust::throttle::{MemoryThrottleStore, Throttle, ThrottleConfig, ThrottleDecision, ThrottleOutcome};

let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());

let key = "acct:user-42";
let now = 1_700_000_000u64;

match throttle.check(key, now) {
    ThrottleDecision::Allow { remaining } => { /* مسموح */ }
    ThrottleDecision::Banned { until } => { /* محظور */ }
    ThrottleDecision::Unavailable => { /* تعذّر الوصول إلى المخزن */ }
}
// فحص عدة أبعاد معًا (مثل IP + الحساب): النتيجة الأكثر صرامة هي المعتمدة
let merged = throttle.check_any(&["ip:203.0.113.7", "acct:user-42"], now);  // ThrottleDecision
let outcome = throttle.record_failure(key, now)?;  // Result<ThrottleOutcome, StoreError>
throttle.record_success(key)?;       // Result<(), StoreError>
throttle.reset(key)?;                // Result<(), StoreError>
throttle.purge_expired(now)?;        // Result<usize, StoreError>
```

- افتراضات `ThrottleConfig`: `threshold` = 5، و`window_secs` = 60، و`ban_secs` = 900
- `check_any(&[key, ...], now)` يدمج عدة أبعاد: أي `Banned` يفوز (بأبعد `until`)، وإلا `Unavailable`، وإلا `Allow` بأصغر `remaining`؛ وتمرير قائمة فارغة يعطي `Allow { remaining: 0 }`
- `ThrottleOutcome` (`Allow { remaining }` | `Banned { until }`) هو ناتج `record_failure`؛ ولا يحوي `Unavailable` لأن فشل المخزن يعود هناك على شكل `Err(StoreError)`
- **استثناء مقصود**: عند تعطّل المخزن تُعيد `check` / `check_any` قيمة `Unavailable` وليس `Banned` — الحد من المعدل دفاع في العمق وليس البوابة الأساسية للمصادقة، ومنع جميع المستخدمين بسبب خلل في الخلفية هو حجب للذات (self-DoS)، وقرار التصرف متروك للمستدعي
- المخزن مجرّد عبر trait `ThrottleStore` والتنفيذ الجاهز `MemoryThrottleStore`

### `score` — تقييم المخاطر

```rust
use security_rust::{assess, Scanner};

// استخدم حمولة بإشارة قوية: مجرد وجود الوسم إشارة ضعيفة (Low، 5 نقاط)
let results = Scanner::default().scan("<img src=x onerror=alert(1)>");
let a = assess(&results);
println!("{} {}", a.level, a.score);   // CRITICAL 100

let a = Scanner::default().assess("<img src=x onerror=alert(1)>");  // RiskAssessment مباشرة
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
| حيوان المشروع | `src/pet.rs` | — |

## الحدود المعروفة

ما يلي **حدود معروفة ومقصود الإبقاء عليها**، وليست عيوبًا تنتظر الإصلاح. اقرأ السند قبل أي تغيير — فكل حدٍّ منها مستخلص من قياس فعلي، وكلًّا منها حاول أحدهم تضييقه فارتطم بالجدار نفسه.

### `dns_rebinding` يُبلّغ ولا يحجب

معياره هو «ظهور عنوان داخلي في `Host:`»، وهذا الشكل نفسه هو كل نداء بين حاويتين في k8s (`Host: 10.244.1.5:8080`)، وكل تطوير محلي (`Host: localhost:8000`)، وكل طلب على شبكة حاوية Docker (`172.18.0.2`). أما إعادة الربط الحقيقية فهي «نطاق عام + نتيجة تحليل تشير إلى الداخل»، والـ`Host` الذي يرسله المتصفح هو ذلك النطاق العام نفسه — **فإن سلسلة واحدة لا تحمل تاريخ التحليل**، والشكل الذي يقيسه هذا الكاشف لا ينطبق على شكل الهجوم، ولا سبيل إلى تضييقه. لذلك هذا الكاشف ضعيف بكامله ويُبلَّغ دائمًا بـ`Low`، ومهما تراكمت إصاباته فلن يتجاوز حد الرفض منفردًا. والحماية تكون بمقارنة عنوان IP **بعد** التحليل، لا في طبقة النصوص.

### هذه المكتبة لا تستطيع فحص شيفرتها واختباراتها وتوثيقها

هذا هو سقف كاشف التواقيع: بالقياس، في هذا المستودع 78 ملفًا من أصل 298 تتجاوز حد الرفض، وكلها تحتوي سلاسل هجومية **بحكم بنائها** — حِمْلات الاختبار، والتعبيرات المنتظمة المكتوبة في شيفرة الكاشفات نفسها، وجداول README وOWASP التي تسرد هذه الأنماط. فملف README لا يصير معيبًا لأنه يذكر `(a+)+`. ولكي تفحص مخرجاتك أنت، عليك أولًا استثناء هذه المدونة، أو اختيار معيار آخر.

### `upload` يُبلّغ عن `<%@` / `<?php` بخطورة Critical دائمًا

عقد هذا الكاشف هو «**هذه الكتلة شيفرة قابلة للتنفيذ على الخادم**» — أي إن الظهور وحده كافٍ، فلا يُقسَّم هنا إلى مستويين. فبادئة صفحة JSP وبادئة JSP webshell متطابقتان بايتًا ببايت (`<%@ page language="java" … %>` و`<%@ page import="java.io.*" %>` شكل واحد)، وإنزال `<%@`/`<%=` إلى المستوى الضعيف يُسقط webshell تحت حد الرفض — أي حذف للكاشف بصيغة أخرى. والثمن أن فحص صفحة **تُقدَّم للزوار الآن** (لا ملفًا مرفوعًا) يصيب أيضًا، وذلك عدم تطابق في نطاق المدخل.

### `path_traversal` يُبلّغ عن `(?:\.\./){2,}` بخطورة Critical

المسارات النسبية العميقة في المستودعات الأحادية (`from '../../../shared/domain'`) تصيب. ولم يُضيَّق أكثر، لأن القيد الوحيد الذي يفصلها عن الهجوم هو قائمة بأسماء الملفات المستهدفة (مثل `../etc/passwd`)، وهي تغطي ملفات النظام وحدها — فالمهاجم يختار هدف LFI آخر وينجو.

## الأداء

مع بناء Release، يحتفظ كل كاشف بجدول ساكن من الأنماط `static PATTERNS: LazyLock<Vec<Regex>>`، فتُجمَّع كل تعبير منتظم مرة واحدة عند أول استخدام داخل العملية ثم يُعاد استخدامه في كل استدعاء لاحق دون أي تكلفة تجميع. وفحص جميع الكاشفات الـ 32 يقع في حدود عشرات الميكروثانية في المرة، ويزداد مع عدد الكاشفات وطول المدخل؛ لذا يُستحسن القياس على العتاد والحمل الفعليين. مناسب لسيناريوهات الإنتاجية العالية (بوابات API وخطوط أنابيب السجلات).
