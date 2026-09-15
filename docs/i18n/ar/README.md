<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust

**🌐 [中文 (原文)](../../README.md)**

مكتبة كشف الهجمات مكتوبة بلغة Rust، تغطي 4 فئات رئيسية بإجمالي 32 كاشفًا: هجمات الحقن، وهجمات البروتوكول، وهجمات البيانات/التسلسل، وتسريب الملفات/البيانات الحساسة. الاعتمادية الخارجية الوحيدة هي `regex`، وكل كاشف فحص نقي للسلاسل النصية. إضافة إلى ذلك توفّر المكتبة وحدات اختيارية ذات حالة (`session` و`throttle`) ووحدة `score` لتجميع المخاطر.

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

---

## بنية التصميم

```
                       ┌──────────────────────────────────┐
                       │             Scanner              │
                       │  ┌────────────────────────────┐  │
    user input ───────►│  │ scan(input)                │  │      Vec<DetectionResult>
                       │  │ scan_with(input, &[...])   │──┼──►──────────────────────►
                       │  └─────────────┬──────────────┘  │
                       │                │                  │
                       │  ┌─────────────▼──────────────┐  │
                       │  │   Vec<Box<dyn Detector>>   │  │
                       │  │   ├─ XssDetector           │  │
                       │  │   ├─ SqlInjectionDetector  │  │
                       │  │   ├─ ... ×32               │  │
                       │  └────────────────────────────┘  │
                       └──────────────┬───────────────────┘
                                      │
       ┌──────────────────────────────┐
       │       Detector trait         │
       │  fn name(&self) -> &str      │
       │  fn detect(&self, &str)      │
       │       -> Option<Result>      │
       └──────────────┬───────────────┘
                      │
       ┌──────────────┼──────────────┐
       │              │              │
  ┌────┴────┐  ┌──────┴──────┐  ┌───┴────┐  ┌────┴────┐
  │injection│  │  protocol   │  │  data  │  │  file   │
  │  11 个  │  │   11 个     │  │ 7 个   │  │  3 个   │
  └─────────┘  └─────────────┘  └────────┘  └─────────┘
```

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
- **`throttle`** — الحد من المعدل والمنع: نافذة منزلقة + عتبة تمنع + قفل الحساب. توفّر `Throttle<S: ThrottleStore>` مع `check`/`record_failure`/`record_success`/`reset`/`purge_expired`، وتُعيد `ThrottleDecision { Allow { remaining }, Banned { until }, Unavailable }`. الافتراضات: threshold 5، وwindow_secs 60، وban_secs 900. وهذا **استثناء مقصود**: عند تعطّل المخزن تُعيد `Unavailable` وليس `Banned` — منع جميع المستخدمين بسبب خلل في الخلفية هو حجب للذات (self-DoS)، وقرار التصرف يبقى للمستدعي.
- **`score`** — تقييم المخاطر: تجميع الإشارات الفردية منخفضة الخطورة في كمية قابلة للقياس، لضبط حدّ الإنذار الكاذب. `RiskLevel { None, Low, Medium, High, Critical }`، و`RiskAssessment`، و`Scanner::assess(&str) -> RiskAssessment`.

تستخدم `session` و`throttle` تجريدًا عبر trait للمخزن، لذا يكفي تنفيذ هذا الـ trait للاتصال بـ Redis عند التشغيل على عدة نسخ.

---

## الميزات المنفذة

### هجمات الحقن (11 كاشفًا)

| الكاشف | الأنماط المغطاة | الخطورة |
|--------|---------|--------|
| **xss** | `<script>` و`onerror=` ومعالجات الأحداث المماثلة، البروتوكول الزائف `javascript:`، وسوم `<svg>`/`<iframe>`، `expression()` في CSS، `eval()`، `document.cookie` | Critical |
| **sql_injection** | `UNION SELECT`، حقن التأخير عبر `sleep()`/`benchmark()`/`pg_sleep()`، تعداد `information_schema`، الإجراءات المخزنة `exec sp_`/`xp_`، نمط الحقن الأعمى المنطقي `' OR '1'='1`، `LOAD_FILE()`/`INTO OUTFILE` | Critical |
| **command_injection** | أوامر علامة الاقتباس الخلفية، أوامر فرعية `$()`، تنفيذ متسلسل عبر الأنابيب `|`، قشرة عائدة عبر `/dev/tcp`، دوال PHP `passthru()`/`shell_exec()`/`system()`، استدعاءات `cmd.exe`/`powershell` | Critical |
| **nosql_injection** | عوامل تشغيل MongoDB `$ne`/`$gt`/`$regex`/`$where`، حقن `$or`، تجاوز المصادقة عبر `{"$gt": ""}` | Critical |
| **ldap_injection** | عوامل فلاتر `(&` `(|` `(!`، تعداد الخصائص `*(cn=`، حقن `objectClass`/`uid` | High |
| **xpath_injection** | تجاوز منطقي `' or '1'='1`، حقن دالة `' or true()`، اجتياز العقد `'] | '` | High |
| **jndi_injection** | `${jndi:ldap://`، تشويش `${lower:j}`، تشويش `${upper:j}`، تشويش السلسلة الفارغة `${::-j}`، البحث في متغيرات البيئة `${env:}`، خصائص النظام `${sys:}` | Critical |
| **ssi_injection** | تنفيذ أوامر `<!--#exec cmd=`، تضمين ملف `<!--#include file=`، إخراج متغير `<!--#echo var=`، معلومات الملفات `<!--#fsize`/`<!--#flastmod` | High |
| **graphql_injection** | استعلامات الفحص الداخلي `__schema`/`__type`، DoS بالتدرج العميق (≥5 مستويات) | Medium |
| **ssti** | Jinja2 `{{}}`، FreeMarker `${}`، ERB `<%=` `<%@`، Velocity `#set()`، هروب من الصندوق الرمل عبر MRO في بايثون `__mro__`/`__subclasses__()` | Critical |
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
| **cors** | تجاوز `Origin: null`، تركيبة `Access-Control-Allow-Origin: *` + Credentials | Medium |
| **websocket** | مصافحة `Upgrade: websocket`، WS عبر النطاقات بـ `Origin: null`، اتصال نصي صريح `ws://` | High |
| **dns_rebinding** | رأس Host بعناوين IP داخلية `127.x`/`10.x`/`192.168.x`/`172.16-31.x`، `localhost`، `::1`، `0.0.0.0` | High |
| **log4shell** | تشويش `${lower:j}`/`${upper:j}`، وتشويش السلسلة الفارغة `${::-j}`، والبحث المتداخل `jndi`، والنظير المرمّز بـ URL `%24%7b...%3a...%7d...ndi` | Critical |
| **hpp** | تكرار المفتاح نفسه للمعامل (`a=1&a=2`)، والخلط بين `&` و`;` لنفس المفتاح — مع استثناء `;jsessionid=` الخاص بمعاملات المصفوفة في حاويات Java | Medium |

### هجمات البيانات والتسلسل (7 كاشفات)

| الكاشف | الأنماط المغطاة | الخطورة |
|--------|---------|--------|
| **deserialization** | كائنات متسلسلة PHP `O:رقم:`/`C:رقم:`، مصفوفات `a:رقم:{`، استدعاءات `unserialize()`، طرق سحرية `__wakeup`/`__destruct`/`__toString` وما يشابهها | Critical |
| **csv_injection** | أحرف صيغ بداية الخلية `=`/`+`/`-`/`@`، تبادل البيانات الديناميكي DDE، أنبوب أوامر `cmd|`، دالة `@SUM()` | Medium |
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

## دليل الاستخدام

يعمل بدون أي إعداد:

```rust
use security_rust::Scanner;

let scanner = Scanner::default();
let results = scanner.scan("<script>alert('xss')</script>");
// [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
```

مرجع API الكامل (التثبيت، الفحص الانتقائي، الإعدادات المخصصة، عرض الخطورة، الأداء) في [مرجع API](./API.md).

---

## التطوير

```bash
# بناء
cargo build --release

# اختبار (354 اختبار وحدة + 108 اختبارات تكاملية = 462)
cargo test

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
