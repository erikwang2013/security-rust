<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust

**🌐 [中文 (原文)](../../../README.md)**

مكتبة كشف الهجمات مكتوبة بلغة Rust، تغطي 4 فئات رئيسية بإجمالي 32 كاشفًا: هجمات الحقن، وهجمات البروتوكول، وهجمات البيانات/التسلسل، وتسريب الملفات/البيانات الحساسة. الاعتمادية الخارجية الوحيدة هي `regex`، وكل كاشف فحص نقي للسلاسل النصية. إضافة إلى ذلك توفّر المكتبة وحدات اختيارية ذات حالة (`session` و`throttle`) ووحدة `score` لتجميع المخاطر.

حيوان المشروع **甲哨 Sentri** ([`pet.svg`](../../pet.svg)) — 32 صفيحة درعية مقابل 32 كاشفًا؛ يُبلّغ عن كل شيء ولا يعترض شيئًا.

---

## حيوان المشروع: 甲哨 Sentri

<img src="../../pet.svg" alt="甲哨 Sentri — حيوان مشروع security-rust" width="340">

سلطعون حِراسة يحمل عدسة مكبِّرة ولافتة. الشخصية ليست زخرفًا — بل هي تصميم هذه المكتبة مرسومًا:

| السمة | ما يقابله في التصميم |
|------|---------|
| 4 صفوف × 8 صفائح على الدرع | 32 كاشفًا بلا حالة؛ والصفوف الأربعة هي الحقن / البروتوكول / البيانات / الملفات |
| العدسة المكبِّرة في الكمّ الأيسر | **النظر** — `Detector::detect()` يكتفي بالفحص، وعند الإصابة يُعيد دليلًا واحدًا |
| اللافتة في الكمّ الأيمن (`已上报` — «تم الإبلاغ») | **الإبلاغ** — يُعيد `DetectionResult`، لا يطرح استثناءً ولا يقطع سلسلة الاستدعاء |
| كمّاشات لا تقرص أبدًا | القرار للمستدعي؛ والاستثناء الوحيد هو `SessionGuard`، فهو فعلًا ينفّذ `Block` |
| العدسة المفردة (المونوكل) | مهنة المدقّق: كل نتيجة تحمل `matched_pattern` و`offset`، فيمكن ردّها إلى موضعها في النص الأصلي |
| `deps: regex ×1` على لوحة الاسم | وعد صفر الاعتماديات: `[dependencies]` لا يحوي إلا `regex` |

الشعار: **يُبلّغ فقط، ولا يعترض.**

الرسم مُضمَّن في المكتبة عبر `include_str!` (بلا كلفة وقت تشغيل — ولا يُربَط إن لم تستخدمه)، ويمكن طبع نسخة ASCII مباشرة في الطرفية أو في السجل:

```rust
println!("{}", security_rust::pet::ASCII);
```

---

## بنية المشروع

```
security-rust/
├── src/
│   ├── lib.rs              trait Detector (العقد الوحيد)، ومساعد regex_detect، وتوثيق الـ crate
│   ├── scanner.rs          Scanner / ScannerBuilder: يركّب الكاشفات الـ 32 كلها افتراضيًا
│   ├── result.rs           DetectionResult / AttackCategory / Severity
│   ├── score.rs            تقييم المخاطر: تجميع موزون + تدريج → RiskAssessment
│   ├── pet.rs              حيوان المشروع (NAME / TAGLINE / ASCII / SVG)
│   ├── injection/          11 كاشفًا للحقن
│   ├── protocol/           11 كاشفًا للبروتوكول
│   ├── data/               7 كاشفات للبيانات
│   ├── file/               3 كاشفات للملفات
│   ├── session/            SessionGuard + SessionStore (guard / store / geo)
│   └── throttle/           Throttle + ThrottleStore (guard / store)
├── tests/                  7 مجموعات اختبار تكاملي: الجلسة، الحد من المعدل، دورة الحياة، الثوابت، المتانة، من البداية إلى النهاية، الحد متعدد المفاتيح
├── examples/
│   ├── waf.rs              مثال المسار الكامل من البداية إلى النهاية (فحص → حد من المعدل → جلسة → إجراء)
│   └── axum_middleware.rs  مرجع دمج وسيط axum
├── docs/
│   ├── API.md              مرجع API الكامل
│   ├── OWASP-COVERAGE.md   مصفوفة التغطية مقابل فئات هجمات OWASP
│   ├── pet.svg             رسم حيوان المشروع
│   ├── diagrams/           مخططات البنية / الميزات / دورة الحياة (SVG)
│   ├── i18n/               وثائق README و API بـ 12 لغة
│   └── ...                 رموز التبرع وتقارير مراجعة الكود والاختبار
└── Cargo.toml              الاعتمادية الوحيدة في وقت التشغيل: regex
```

---

## مفهوم التصميم

### لماذا «الكشف» بدل «الاعتراض»

تعتبر هذه المكتبة **ماسحًا نقيًا للمدخلات** — تستقبل سلسلة نصية وتعيد نتائج كشف منظمة. لا ترتبط بأي إطار ويب، ولا تحلل طلبات/استجابات HTTP، ولا تنفذ حظرًا فوريًا. بهذه الطريقة يمكنك تضمينها في أي مسار: محركات قواعد WAF، وتدقيق السجلات، والتحقق المسبق أمام بوابات API، وأدوات فحص الأمان عبر CLI، وغيرها.

تنطبق هذه الصفة على `Scanner` و`Detector` حصرًا. أما `session` و`throttle` فهما استثناءان مقصودان: كلاهما **ذو حالة ومرتبط بالهوية** (توكن + بصمة عميل + موقع + وقت)، وهو مدخل مركّب لا يستطيع `Detector::detect(&str)` التعبير عنه — لذلك لا تنفذه هذه الوحدات عمدًا.

### مبادئ البنية

- **المسؤولية الواحدة** — كل كاشف مسؤول عن نوع هجوم واحد فقط، ويحمل داخليًا مجموعة أنماط تعبيرات منتظمة مُجمّعة مسبقًا
- **واجهة موحدة** — trait `Detector` هو العقد الوحيد لجميع الكاشفات: `fn detect(&self, input: &str) -> Option<DetectionResult>`
- **تغطية افتراضية** — `Scanner::default()` يركّب جميع الكاشفات الـ 32 بضغطة واحدة، ويعمل بدون أي إعداد
- **إعدادات اختيارية** — يدعم `Scanner::builder()` التخصيص حسب الحاجة، عبر `.with_detector()` لتجميع الكاشفات انتقائيًا

### المقايضات

| القرار | الاختيار | السبب |
|------|------|------|
| تعبيرات منتظمة مقابل محلل | تعبيرات منتظمة | في سيناريوهات الكشف، السرعة أولوية، والتعبيرات المنتظمة تغطي أنماط التشويه/الالتفاف بشكل أفضل |
| الإبلاغ الأول مقابل الكشف الشامل | الكشف الشامل | قد يثير المدخل الواحد عدة هجمات في نفس الوقت، فلا ينبغي تفويت أي منها |
| صفر اعتماديات مقابل إدخال serde | صفر اعتماديات | يعتمد على `regex` فقط — حتى الوحدات ذات الحالة تُمرِّر التخزين عبر trait، فلا اعتمادية جديدة، تجميع سريع وحجم صغير |
| الكاشفات مقابل الوحدات ذات الحالة | فصلها | `Detector::detect(&str)` له معامل نصي وحيد ولا يعبّر عن المدخل المركّب «توكن + بصمة + موقع + وقت»، لذلك استُقلّت `session` / `throttle` عن `Scanner` |
| fail-closed مقابل fail-open | المصادقة fail-closed، والحد من المعدل fail-open | السماح في قرار الجلسة يعني تجاوزًا، فيجب الحجب؛ أما الحد من المعدل فحجب جميع المستخدمين هو DoS ذاتي، والبوابة الرئيسية للمصادقة لا تزال تحجب، وقرار التصرف يُترك للمستدعي |

---

## بنية التصميم

<img src="../../diagrams/architecture.svg" alt="بنية security-rust: المستدعي → طبقة الكشف → طبقة التقييم → طبقة الحرّاس → التخزين" width="900">

خمس طبقات من الأعلى إلى الأسفل: **المستدعي** (WAF / بوابة / تدقيق / CLI) → **طبقة الكشف** (`Scanner` يحمل `Vec<Box<dyn Detector>>`، و32 كاشفًا في 4 فئات) → **طبقة التقييم** (`score::assess`) → **طبقة الحرّاس** (`SessionGuard` / `Throttle`، وكل منهما مرتبط بـ trait للمخزن) → **تجريد التخزين** (المخزن المدمج `MemoryStore`، أما Redis فينفّذه المستدعي).
*(تعليقات المخططات بالصينية؛ أما التسميات فهي أسماء API.)*

الـ trait `Detector` هو العقد الوحيد لطبقة الكشف: `fn detect(&self, input: &str) -> Option<DetectionResult>`. ولا تنفّذه `session` و`throttle` و`score` — فمدخلها ليس سلسلة واحدة (توكن + بصمة + موقع + وقت)، أو أنها تستهلك نتائج الفحص بدل المدخل الخام — لذلك تجيب كل واحدة على حدة، كما هو موضّح أدناه. أما خط الإرجاع الأحمر على اليمين فيحدّد تخوم المكتبة: **الحكم يعود إلى المستدعي لينفّذه**؛ والمكتبة لا تلمس الطلب نفسه أبدًا.

### مسؤوليات الوحدات

| الوحدة | المسار | عدد الكاشفات | المسؤولية |
|------|------|---------|------|
| النواة | `src/lib.rs` `result.rs` `scanner.rs` | — | trait `Detector`، `DetectionResult`، `Scanner`/`ScannerBuilder` |
| الحقن | `src/injection/` | 11 | XSS، SQL Injection، Command Injection، NoSQL، LDAP، XPATH، JNDI، SSI، GraphQL، SSTI، حقن سلاسل التنسيق |
| البروتوكول | `src/protocol/` | 11 | SSRF، XXE، حقن الترويسات، هجوم رأس Host، تهريب الطلبات، إعادة توجيه مفتوحة، CORS، WebSocket، إعادة ربط DNS، Log4Shell، تلوث معاملات HTTP |
| البيانات | `src/data/` | 7 | إلغاء تسلسل PHP، حقن صيغ CSV، حقن ترويسات البريد، هجمات JWT، تلوث النماذج الأولية، حقن صيغ الجداول، كشف ReDoS |
| الملفات | `src/file/` | 3 | اجتياز المسار، رفع ملفات خبيثة، تسريب بيانات حساسة |
| الجلسات | `src/session/` | — | `SessionGuard`، `RequestContext`، `SessionVerdict`، `SessionConfig`، trait `SessionStore` + `MemoryStore` |
| الحد من المعدل | `src/throttle/` | — | `Throttle`، `ThrottleDecision`، `ThrottleConfig`، trait `ThrottleStore` + `MemoryThrottleStore` |
| تقييم المخاطر | `src/score.rs` | — | `RiskLevel`، `RiskAssessment`، `assess()` |

### بنية نتيجة الكشف

يُعيد `DetectionResult` بشكل منظم ستة حقول: `attack_type` و`category` و`severity` و`matched_pattern` و`offset` و`message`. راجع [مرجع API](./API.md) للتعريف الكامل.

### الوحدات ذات الحالة وتقييم المخاطر

لا تنفّذ `session` و`throttle` الـ trait `Detector` عمدًا، لأن مدخلاتها مركّبة (توكن + بصمة + موقع + وقت) ولا يعبّر عنها `Detector::detect(&str)`. تشكّل الوحدات الثلاث التالية الطبقة التي تعلو الفحص النصي:

- **`session`** — أمان الجلسات: اختطاف العميل، والتلاعب بالبيانات، وتسجيل الدخول من موقع آخر، وجلسات التوكن. توفّر `SessionGuard<S: SessionStore>` مع `bind`/`verify`/`revoke`/`revoke_all`/`rotate`. الافتراضات: `ttl_secs` = 3600، و`impossible_travel_kmh` = 900.0، و`timestamp_skew_secs` = 300. عند تعذّر الوصول إلى المخزن تكون النتيجة `Decision::Block` (والسبب `StoreUnavailable`) — أي **fail-closed**، ولا يوجد مسار يسمح بالمرور.
- **`throttle`** — الحد من المعدل والمنع: نافذة منزلقة + عتبة تمنع + قفل الحساب. توفّر `Throttle<S: ThrottleStore>` مع `check`/`check_any`/`record_failure`/`record_success`/`reset`/`purge_expired`، وتُعيد `ThrottleDecision { Allow { remaining }, Banned { until }, Unavailable }`. الافتراضات: threshold 5، وwindow_secs 60، وban_secs 900. وهذا **استثناء مقصود**: عند تعطّل المخزن تُعيد `Unavailable` وليس `Banned` — منع جميع المستخدمين بسبب خلل في الخلفية هو حجب للذات (self-DoS)، وقرار التصرف يبقى للمستدعي. و`record_failure` يُعيد `ThrottleOutcome` (`Allow`/`Banned`) بلا `Unavailable`.
- **`score`** — تقييم المخاطر: تجميع الإشارات الفردية منخفضة الخطورة في كمية قابلة للقياس، لضبط حدّ الإنذار الكاذب. `RiskLevel { None, Low, Medium, High, Critical }`، و`RiskAssessment`، و`Scanner::assess(&str) -> RiskAssessment`.

تستخدم `session` و`throttle` تجريدًا عبر trait للمخزن، لذا يكفي تنفيذ هذا الـ trait للاتصال بـ Redis عند التشغيل على عدة نسخ.

---

## الميزات المنفذة

<img src="../../diagrams/features.svg" alt="مخطط ميزات security-rust: الحقن 11، البروتوكول 11، البيانات 7، الملفات 3، إضافة إلى ثلاث وحدات ذات حالة" width="900">

تُجمَّع الكاشفات الـ 32 حسب الفئات الأربع، وتُفعَّل كلها بلا إعداد عبر `Scanner::default()`؛ وتسرد الجداول التالية الأنماط التي يغطيها كل كاشف وخطورته. والخطورة تصف أثر إصابة واحدة فقط، أما الخطر المجمَّع فيأتي من `Scanner::assess()`.
*(تعليقات المخططات بالصينية؛ أما التسميات فهي أسماء API.)*

### هجمات الحقن (11 كاشفًا)

| الكاشف | الأنماط المغطاة | الخطورة |
|--------|---------|--------|
| **xss** | `<script>` و`onerror=` ومعالجات الأحداث المماثلة، البروتوكول الزائف `javascript:`، وسوم `<svg>`/`<iframe>`، `expression()` في CSS، `eval()`، `document.cookie` | Critical |
| **sql_injection** | `UNION SELECT`، حقن التأخير عبر `sleep()`/`benchmark()`/`pg_sleep()`، تعداد `information_schema`، الإجراءات المخزنة `exec sp_`/`xp_`، نمط الحقن الأعمى المنطقي `' OR '1'='1`، `LOAD_FILE()`/`INTO OUTFILE` | Critical |
| **command_injection** | أوامر علامة الاقتباس الخلفية، أوامر فرعية `$()`، تنفيذ متسلسل عبر الأنابيب `\|`، قشرة عائدة عبر `/dev/tcp`، دوال PHP `passthru()`/`shell_exec()`/`system()`، استدعاءات `cmd.exe`/`powershell` | Critical |
| **nosql_injection** | عوامل تشغيل MongoDB `$ne`/`$gt`/`$regex`/`$where`، حقن `$or`، تجاوز المصادقة عبر `{"$gt": ""}` | Critical |
| **ldap_injection** | عوامل فلاتر `(&` `(\|` `(!`، تعداد الخصائص `*(cn=`، حقن `objectClass`/`uid` | High |
| **xpath_injection** | تجاوز منطقي `' or '1'='1`، حقن دالة `' or true()`، اجتياز العقد `'] \| '` | High |
| **jndi_injection** | `${jndi:ldap://`، تشويش `${lower:j}`، تشويش `${upper:j}`، تشويش السلسلة الفارغة `${::-j}`، البحث في متغيرات البيئة `${env:}`، خصائص النظام `${sys:}` | Critical |
| **ssi_injection** | تنفيذ أوامر `<!--#exec cmd=`، تضمين ملف `<!--#include file=`، إخراج متغير `<!--#echo var=`، معلومات الملفات `<!--#fsize`/`<!--#flastmod` | High |
| **graphql_injection** | استعلامات الفحص الداخلي `__schema`/`__type`، DoS بالتدرج العميق (≥5 مستويات) | Medium |
| **ssti** | Jinja2 `{{ }}` / FreeMarker `${ }` — **تقييم داخل المحددات** (`{{7*7}}`، `${7*7}`، `{{config`، `${T(java.lang.Runtime)}`)، ERB `<%=` `<%@`، Velocity `#set()`، سلاسل الهروب في بايثون `__mro__`/`__subclasses__()`/`__globals__`/`__builtins__`/`__class__`/`__dict__`؛ المحددات وحدها ليست إشارة، فلا يُبلَّغ عن عنصر نائب مثل `${x}` | Critical |
| **format_string** | محددات `%n` لكتابة الذاكرة (`%n`/`%1$n`/`%hn`/`%ln`)، وأحرف تحويل بعرض كبير `%123456d`، وتكرار كثيف لمحددات `%x`/`%p`/`%s` لتسريب الذاكرة | Medium |

### هجمات البروتوكول والطلبات (11 كاشفًا)

| الكاشف | الأنماط المغطاة | الخطورة |
|--------|---------|--------|
| **ssrf** | البيانات الوصفية السحابية `169.254.169.254`، عناوين IP للشبكة الداخلية RFC1918 (10.x، 172.16-31.x، 192.168.x)، حلقة `127.x`، حلقة IPv6 `::1`، `0.0.0.0`، بروتوكولات خطيرة `gopher://`/`dict://`/`ftp://`/`file://` | Critical |
| **xxe** | إعلان كيان `<!ENTITY`، مراجع خارجية `SYSTEM`/`PUBLIC`، كيانات معاملات `%`، إعلانات DTD `<!DOCTYPE` | Critical |
| **header_injection** | CRLF بترميز URL `%0d%0a`، حقن CRLF خام `\r\n` | High |
| **host_header** | حقن رؤوس Host متعددة، تسميم `X-Forwarded-Host`/`X-Original-URL`/`X-Rewrite-URL`، حمل Host عبر CRLF | High |
| **request_smuggling** | رؤوس `Transfer-Encoding` مزدوجة، تهريب `Content-Length: 0`، تشويش إنهاء chunked `\r\n0\r\n` | High |
| **open_redirect** | عناوين نسبية للبروتوكول `//evil.com`، قفزات البروتوكولات الزائفة `javascript:`/`data:text/html` | Medium |
| **cors** | `Access-Control-Allow-Origin: null`، `Origin: null` (المؤشر القياسي لإطارات iframe المعزولة وCSWSH)، و`Access-Control-Allow-Origin: *` **مع** `Access-Control-Allow-Credentials: true`. كلٌّ منهما منفردًا طبيعي في واجهات API العامة والموارد الثابتة ولا يُبلَّغ عنه | Medium |
| **websocket** | `Origin: null` مع ترقية WebSocket في الوقت نفسه (CSWSH)، `ws://` موجّه إلى عناوين loopback أو الخاصة أو link-local (بما فيها نقطة نهاية البيانات الوصفية السحابية `169.254.169.254`) | High |
| **dns_rebinding** | رأس Host بعناوين IP داخلية `127.x`/`10.x`/`192.168.x`/`172.16-31.x`، `localhost`، `::1`، `0.0.0.0` | High |
| **log4shell** | تشويش `${lower:j}`/`${upper:j}`، وتشويش السلسلة الفارغة `${::-j}`، والبحث المتداخل `jndi`، والنظير المرمّز بـ URL `%24%7b...%3a...%7d...ndi` | Critical |
| **hpp** | تكرار المفتاح نفسه للمعامل (`a=1&a=2`)، والخلط بين `&` و`;` لنفس المفتاح — مع استثناء `;jsessionid=` الخاص بمعاملات المصفوفة في حاويات Java | Medium |

### هجمات البيانات والتسلسل (7 كاشفات)

| الكاشف | الأنماط المغطاة | الخطورة |
|--------|---------|--------|
| **deserialization** | كائنات متسلسلة PHP `O:رقم:`/`C:رقم:`، مصفوفات `a:رقم:{`، استدعاءات `unserialize()`، طرق سحرية `__wakeup`/`__destruct`/`__toString` وما يشابهها | Critical |
| **csv_injection** | أحرف الصيغ في بداية الخلية `=`/`+`/`-`/`@` (الجدولة وحرف الإرجاع **فاصلان** وليسا بداية صيغة)، و`=` يلي فاصل `,`/`;`/`\t` مباشرةً، وتبادل البيانات الديناميكي DDE، وأنبوب أوامر `cmd\|`، ودالة `@SUM()` | Medium |
| **mail_header** | حقن نسخة مخفية `Bcc:`/`Cc:`، مرسلون متعددون `From:`، حقن ترويسات MIME `MIME-Version:`/`Content-Type: multipart`، التلاعب بالحدود `boundary=` | Medium |
| **jwt_attack** | تجاوز الخوارزمية الفارغة `alg: none`، حقن اجتياز المسار `kid`، مقطع توقيع فارغ، مقطع payload فارغ | High |
| **prototype_pollution** | تلوث سلسلة النماذج الأولية `__proto__`/`constructor.prototype`، اختطاف الخصائص `__defineGetter__`/`__defineSetter__`/`__lookupGetter__`/`__lookupSetter__` | High |
| **formula_injection** | دوال الجداول الخطيرة `HYPERLINK()`/`IMPORTXML()`/`IMPORTDATA()`/`IMPORTRANGE()`/`WEBSERVICE()`/`RTD()`/`EXEC()`، وتسريب البيانات عبر الصيغة والأنبوب مع مرجع خلية محدد، و`DDE(`، ودوال `@` | High |
| **redos** | محددات كمية متداخلة `(x+)+`/`(x*)*`/`(x{2,})+`، وفروع بديلة ببادئة مشتركة، وتكرار بديل صنف الأحرف | Medium |

### الملفات والبيانات الحساسة (3 كاشفات)

| الكاشف | الأنماط المغطاة | الخطورة |
|--------|---------|--------|
| **path_traversal** | عبور الأدلة `../`/`..\\`، تجاوز بترميز URL `%2e%2e`، أغلفة بروتوكولات `php://filter`/`php://input`/`phar://`/`zip://`/`data://`/`expect://`/`glob://`، اقتطاع بالبايت الفارغ `%00` | Critical |
| **upload** | وسوم PHP `<?php`/`<?=`، وسوم ASP `<%@`/`<%=`، أنماط أبواب خلفية `eval($_`/`system($_`/`exec($_`/`passthru($_`، متغيرات فائقة العمومية `$_GET`/`$_POST`/`$_REQUEST`/`$_SERVER`، تجاوز الترميز `base64_decode()` | Critical |
| **data_leak** | رقم بطاقة ائتمان من 16 خانة (Visa/MasterCard/AmEx/Discover/JCB/Diners)، مفتاح وصول AWS `AKIA...`، ترويسة مفتاح خاص PEM `-----BEGIN`، مفاتيح API لـ OpenAI/LLM `sk-...`، سلاسل اتصال قواعد البيانات `mongodb://`/`mysql://`/`postgresql://`/`redis://`/`jdbc:`، رموز JWT | Critical |

---

## دورة الحياة

<img src="../../diagrams/lifecycle.svg" alt="دورات حياة security-rust: الفحص، الجلسة، الحد من المعدل" width="900">

ثلاث دورات حياة مستقلة عن بعضها، ونقطة التقائها الوحيدة هي دالة معالجة الطلب لدى المستدعي:
*(تعليقات المخططات بالصينية؛ أما التسميات فهي أسماء API.)*

| دورة الحياة | نقطة البداية | نقطة النهاية | موضع الحالة |
|-----------|-----------|---------|----------------|
| **الفحص** | `Scanner::scan(&str)` | `Vec<DetectionResult>` → `score::assess` → `RiskAssessment` | لا شيء — بلا حالة، وكل استدعاء مستقل |
| **الجلسة** | `SessionGuard::bind()` تكتب `SessionRecord` | `verify()` في كل طلب → `SessionVerdict` ⇒ `Allow` / `Challenge` / `Block` | `SessionStore` (المخزن المدمج `MemoryStore`) |
| **الحد من المعدل** | `Throttle::check_any(&[keys])` | `Allow{remaining}` / `Banned{until}` / `Unavailable` | `ThrottleStore` (المخزن المدمج `MemoryThrottleStore`) |

حدّان يسهل الخطأ فيهما:

- **`remaining == 0` يعني أن هذا الطلب يجب رفضه** — فالرصيد استُهلك، وليس «بقيت محاولة أخيرة». لا تكتبه بالعكس عند إخراج ترويسات `X-RateLimit-*`.
- **معالجة عطل المخزن تسير في اتجاهين متعاكسين**: `SessionGuard` يتبع fail-closed (`StoreUnavailable` ⇒ `Block`، ولا يسمح بالمرور أبدًا، وإلا كفى المهاجم أن يستحث عطلًا ليستبدل فئة كاملة من الأحكام)؛ أما `Throttle` فيتبع fail-open (`Unavailable` يُترك للمستدعي، فحجب جميع المستخدمين عند اضطراب الخلفية هو DoS ذاتي، والبوابة الرئيسية `SessionGuard` لا تزال تحجب). هذا قرار تصميم مكتوب، وليس استثناءً ناقصًا.

---

## دليل الاستخدام

يعمل بدون أي إعداد:

```rust
use security_rust::Scanner;

let scanner = Scanner::default();
let results = scanner.scan("<script>alert('xss')</script>");
// [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
```

يجمع تقييم المخاطر قائمة الإصابات في درجة واحدة، حتى لا تُهمَل إشارات متعددة منخفضة الخطورة بصمت:

```rust
let assessment = scanner.assess("=cmd|' /C calc'!A0 `cat /etc/passwd` ../../../etc/passwd");
// assessment.level   >= RiskLevel::High
// assessment.results >= 3
// assessment.score   — الدرجة الموزونة الخام
```

مرجع API الكامل (التثبيت، الفحص الانتقائي، الإعدادات المخصصة، تقييم المخاطر، عرض الخطورة، أمان الجلسات، الحد من المعدل والمنع، الأداء) في [مرجع API](./API.md).

### أمان الجلسات (`session`)

```rust
use security_rust::session::{Decision, MemoryStore, RequestContext, SessionConfig, SessionGuard};

let guard = SessionGuard::new(MemoryStore::new(), SessionConfig::default());

let login = RequestContext {
    token: "tok-abc",
    subject: "u-1",
    fingerprint: "ip=1.2.3.4|ua=curl",   // بصمة العميل، تُربَط عند تسجيل الدخول
    location: Some("CN-BJ"),
    coords: Some((39.9042, 116.4074)),
    signature: None,                      // التوقيع (MAC) يصدره المستدعي
    at: None,
};

// تسجيل الدخول: إنشاء الجلسة + ربط البصمة + تسجيل الموقع؛ والموقع المختلف يؤثر على الـ verdict فقط ولا يمنع الدخول
guard.bind(&login, 1_700_000_000).unwrap();

// التحقق في كل طلب: التوكن نفسه مع بصمة مختلفة ⇒ اختطاف العميل
let verdict = guard.verify(&RequestContext { fingerprint: "ip=5.6.7.8|ua=curl", ..login }, 1_700_000_010);

match verdict.decision {
    Decision::Allow => { /* مسموح */ }
    Decision::Challenge => { /* مسموح مع طلب تحقق ثانٍ: موقع مختلف، انحراف في الساعة، توقيع غير متوقع */ }
    Decision::Block => { /* مرفوض */ }
}
```

### الحد من المعدل والمنع (`throttle`)

```rust
use security_rust::throttle::{MemoryThrottleStore, Throttle, ThrottleConfig, ThrottleDecision};

let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());
let key = "acct:u-1"; // المفتاح يبنيه المستدعي ويطبّعه، ولا يجوز استخدام المدخل الخام مفتاحًا
let now = 1_700_000_000;

// الطلب الحقيقي له بعدان: IP والحساب. check_any يسأل عنهما معًا ويدمجهما حسب الصرامة
match throttle.check_any(&["ip:1.2.3.4", key], now) {
    // يمكن كتابة remaining في X-RateLimit-*؛ **remaining == 0 يعني أن هذا الطلب يجب رفضه**
    ThrottleDecision::Allow { remaining } => { /* الرصيد المتبقي remaining */ }
    // اعتبار now >= until رفعًا للحظر
    ThrottleDecision::Banned { until } => { /* محظور، وuntil موعد رفع الحظر */ }
    // عطل في الخلفية: هذه الوحدة لا تقرر نيابة عن المستدعي (يُنصح بالسماح مع تنبيه)
    ThrottleDecision::Unavailable => { /* خلفية الحد من المعدل غير متاحة */ }
}

// تسجيل فشل مصادقة: بلوغ threshold يعني الحظر. تُعيد ThrottleOutcome (حالتان)،
// وعطل المخزن يمر عبر Err —— فلا حاجة إلى كود ميت لفرع Unavailable لا يُنفَّذ
let _ = throttle.record_failure(key, now);
```

---

## التطوير

```bash
# بناء
cargo build --release

# اختبار (494 اختبارًا: 365 اختبار وحدة + 128 اختبار تكامل + 1 اختبار توثيقي)
cargo test

# مثال المسار الكامل من البداية إلى النهاية (فحص → حد من المعدل → جلسة → إجراء)
cargo run --example waf

# فحص الكود
cargo clippy -- -D warnings
```

---

## التبرع / الرعاية

إذا كان هذا المشروع مفيدًا لك، فنحن نرحب بدعمك بالتبرع (اختياري).

| Alipay | WeChat Pay |
|--------|---------|
| ![Alipay](./alipay.png) | ![WeChat Pay](./weixinpay.png) |

### التحويلات العالمية (حوالات دولية)

【معلومات المستفيد】
- اسم المستفيد: WANG KEXUN
- رقم حساب المستفيد: 881015918251

【البنك المستفيد】
- ZA Bank SWIFT Code: AABLHKHHXXX
- اسم البنك: ZA Bank Limited
- رقم البنك: 387
- عنوان البنك: Core F, Cyberport 3, 100 Cyberport Road, Hong Kong

【البنك الوكيل للحوالات عبر الحدود (عند الحاجة)】

يُرجى الانتباه: هذه معلومات البنك الوكيل للحوالات عبر الحدود (البنك الوسيط)، وليست معلومات البنك المستفيد. يُرجى الاستفسار من البنك المُرسِل عما إذا كانت هناك حاجة لتقديم معلومات البنك الوكيل للحوالات عبر الحدود.

البنك الوكيل للحوالات بالدولار الهونغ كونغي واليوان الصيني والدولار الأمريكي هو Citibank:
- اسم البنك: Citibank N.A. Hong Kong
- SWIFT Code: CITIHKHXXXX
- رقم البنك: 006
- اسم الفرع: Hong Kong Branch
- رقم الفرع: 391
- عنوان البنك: Citibank Tower, Citibank Plaza, 3 Garden Road, Central, Hong Kong

أما البنك الوكيل للحوالات بالعملات الأخرى فهو BNY Mellon:
- اسم البنك: THE BANK OF NEW YORK MELLON
- SWIFT Code: IRVTUS3NXXX
- عنوان البنك: THE BANK OF NEW YORK MELLON, 240 GREENWICH STREET, NEW YORK, United States

---

## الترخيص

MIT — Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
