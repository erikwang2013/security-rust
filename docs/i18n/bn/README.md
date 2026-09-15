<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust

**🌐 [中文 (原文)](../../README.md)**

Rust-এ লেখা একটি আক্রমণ শনাক্তকরণ লাইব্রেরি, যা ৪টি প্রধান বিভাগে ৩২টি ডিটেক্টর কভার করে: ইনজেকশন আক্রমণ, প্রোটোকল আক্রমণ, ডেটা/সিরিয়ালাইজেশন আক্রমণ এবং ফাইল/সংবেদনশীল ডেটা ফাঁস। একমাত্র বাহ্যিক নির্ভরতা `regex`, এবং প্রতিটি ডিটেক্টর সম্পূর্ণ স্ট্রিং স্ক্যানিং। এর পাশাপাশি লাইব্রেরিতে ঐচ্ছিক স্টেটফুল মডিউল (`session` ও `throttle`) এবং ঝুঁকি স্কোরিংয়ের জন্য `score` মডিউল রয়েছে।

---

## ডিজাইন দর্শন

### কেন "শনাক্তকরণ" ("ইন্টারসেপশন" নয়)

এই লাইব্রেরিটি একটি **বিশুদ্ধ ইনপুট স্ক্যানার** হিসেবে ডিজাইন করা হয়েছে — এটি স্ট্রিং গ্রহণ করে এবং গঠনমূলক শনাক্তকরণ ফলাফল ফেরত দেয়। এটি কোনো ওয়েব ফ্রেমওয়ার্কের সাথে আবদ্ধ নয়, HTTP অনুরোধ/প্রতিক্রিয়া পার্স করে না এবং রিয়েল-টাইম ব্লকিং বাস্তবায়ন করে না। ফলে আপনি এটিকে যেকোনো পাইপলাইনে এমবেড করতে পারেন: WAF রুল ইঞ্জিন, লগ অডিট, API গেটওয়ে প্রি-ভ্যালিডেশন, CLI সিকিউরিটি স্ক্যানিং টুল ইত্যাদি।

এই বর্ণনা `Scanner` ও `Detector`-এর ক্ষেত্রেই প্রযোজ্য। `session` ও `throttle` ইচ্ছাকৃত ব্যতিক্রম: দুটোই **স্টেটফুল ও পরিচয়-কেন্দ্রিক** (টোকেন + ক্লায়েন্ট ফিঙ্গারপ্রিন্ট + অবস্থান + সময়) — এটি এমন একটি যৌগিক ইনপুট যা `Detector::detect(&str)` প্রকাশ করতে পারে না, তাই এই মডিউলগুলো ইচ্ছাকৃতভাবে এটি প্রয়োগ করে না।

### স্থাপত্য নীতি

- **একক দায়িত্ব** — প্রতিটি ডিটেক্টর শুধুমাত্র একটি আক্রমণের ধরন দেখাশোনা করে এবং অভ্যন্তরীণভাবে কম্পাইল করা রেজেক্স প্যাটার্নের সেট ধারণ করে
- **ইউনিফাইড ইন্টারফেস** — `Detector` trait হল সব ডিটেক্টরের একমাত্র চুক্তি: `fn detect(&self, input: &str) -> Option<DetectionResult>`
- **ডিফল্ট কভারেজ** — `Scanner::default()` একটি ক্লিকে সব ৩২টি ডিটেক্টর একত্রিত করে, শূন্য কনফিগারেশনে ব্যবহারযোগ্য
- **ঐচ্ছিক কনফিগারেশন** — `Scanner::builder()` চাহিদা অনুযায়ী কাস্টমাইজেশন সমর্থন করে, `.with_detector()` দিয়ে ডিটেক্টর নির্বাচনীভাবে সাজানো যায়

### ট্রেড-অফ

| সিদ্ধান্ত | পছন্দ | কারণ |
|------|------|------|
| রেজেক্স বনাম পার্সার | রেজেক্স | শনাক্তকরণ পরিস্থিতিতে গতি প্রাধান্য পায়, রেজেক্স বিকৃত/বাইপাস প্যাটার্নের কভারেজে ভালো |
| প্রথম-ম্যাচ বনাম পূর্ণ স্ক্যান | পূর্ণ স্ক্যান | একটি ইনপুট একসাথে একাধিক ধরনের আক্রমণ ট্রিগার করতে পারে, মিস রিপোর্ট করা উচিত নয় |
| শূন্য নির্ভরতা বনাম serde আনা | শূন্য নির্ভরতা | শুধুমাত্র `regex`-এর উপর নির্ভর করে — স্টেটফুল মডিউলগুলোও স্টোরেজ trait-এর মাধ্যমে নেয়, তাই নতুন কোনো নির্ভরতা নেই; কম্পাইল দ্রুত এবং সাইজ ছোট |

---

## ডিজাইন আর্কিটেকচার

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

### মডিউলের দায়িত্ব

| মডিউল | পাথ | ডিটেক্টর সংখ্যা | দায়িত্ব |
|------|------|---------|------|
| কোর | `src/lib.rs` `result.rs` `scanner.rs` | — | `Detector` trait, `DetectionResult`, `Scanner`/`ScannerBuilder` |
| ইনজেকশন | `src/injection/` | 11 | XSS, SQL ইনজেকশন, কমান্ড ইনজেকশন, NoSQL, LDAP, XPATH, JNDI, SSI, GraphQL, SSTI, ফরম্যাট স্ট্রিং ইনজেকশন |
| প্রোটোকল | `src/protocol/` | 11 | SSRF, XXE, হেডার ইনজেকশন, Host হেডার আক্রমণ, রিকোয়েস্ট স্মাগলিং, ওপেন রিডাইরেক্ট, CORS, WebSocket, DNS রিবাইন্ডিং, Log4Shell, HTTP প্যারামিটার পলিউশন |
| ডেটা | `src/data/` | 7 | PHP ডিসিরিয়ালাইজেশন, CSV ফর্মুলা ইনজেকশন, ইমেইল হেডার ইনজেকশন, JWT আক্রমণ, প্রোটোটাইপ পলিউশন, স্প্রেডশিট ফর্মুলা ইনজেকশন, ReDoS শনাক্তকরণ |
| ফাইল | `src/file/` | 3 | পাথ ট্রাভার্সাল, ম্যালিসিয়াস ফাইল আপলোড, সংবেদনশীল ডেটা ফাঁস |
| সেশন | `src/session/` | — | `SessionGuard`, `RequestContext`, `SessionVerdict`, `SessionConfig`, `SessionStore` trait + `MemoryStore` |
| রেট লিমিট | `src/throttle/` | — | `Throttle`, `ThrottleDecision`, `ThrottleConfig`, `ThrottleStore` trait + `MemoryThrottleStore` |
| ঝুঁকি স্কোরিং | `src/score.rs` | — | `RiskLevel`, `RiskAssessment`, `assess()` |

### শনাক্তকরণ ফলাফলের গঠন

`DetectionResult` কাঠামোবদ্ধভাবে ছয়টি ক্ষেত্র ফেরত দেয়: `attack_type`, `category`, `severity`, `matched_pattern`, `offset`, `message`। সম্পূর্ণ সংজ্ঞার জন্য দেখুন [API রেফারেন্স](./API.md)।

### স্টেটফুল মডিউল ও ঝুঁকি স্কোরিং

`session` ও `throttle` ইচ্ছাকৃতভাবে `Detector` trait প্রয়োগ করে না, কারণ তাদের ইনপুট যৌগিক — টোকেন + ফিঙ্গারপ্রিন্ট + অবস্থান + সময় — যা `Detector::detect(&str)` প্রকাশ করতে পারে না। নিচের তিনটি মডিউল স্ট্রিং স্ক্যানিংয়ের উপরের স্তর গঠন করে:

- **`session`** — সেশন নিরাপত্তা: ক্লায়েন্ট হাইজ্যাকিং, ডেটা টেম্পারিং, ভিন্ন স্থান থেকে লগইন, টোকেন সেশন। এতে রয়েছে `SessionGuard<S: SessionStore>`: `bind`/`verify`/`revoke`/`revoke_all`/`rotate`। ডিফল্ট: `ttl_secs` = 3600, `impossible_travel_kmh` = 900.0, `timestamp_skew_secs` = 300। স্টোর ব্যর্থ হলে ফলাফল `Decision::Block` (কারণ `StoreUnavailable`) — অর্থাৎ **fail-closed**, পাস করার কোনো পথ নেই।
- **`throttle`** — রেট লিমিট ও নিষিদ্ধকরণ: স্লাইডিং উইন্ডো + থ্রেশহোল্ড নিষিদ্ধকরণ + অ্যাকাউন্ট লক। এতে রয়েছে `Throttle<S: ThrottleStore>`: `check`/`record_failure`/`record_success`/`reset`/`purge_expired`, এবং এটি ফেরত দেয় `ThrottleDecision { Allow { remaining }, Banned { until }, Unavailable }`। ডিফল্ট: threshold 5, window_secs 60, ban_secs 900। এটি **ইচ্ছাকৃত ব্যতিক্রম**: স্টোর ব্যর্থ হলে এটি `Banned` নয়, `Unavailable` ফেরত দেয় — ব্যাকএন্ড গোলযোগে সব ব্যবহারকারীকে আটকে দেওয়া হলো নিজের বিরুদ্ধে DoS, আর সিদ্ধান্ত কলারের হাতে থাকে।
- **`score`** — ঝুঁকি স্কোরিং: আলাদা আলাদা নিম্ন-গুরুতার সংকেতকে পরিমেয় মানে সমন্বয় করা, যাতে ফলস-পজিটিভ সীমা টিউন করা যায়। `RiskLevel { None, Low, Medium, High, Critical }`, `RiskAssessment`, এবং `Scanner::assess(&str) -> RiskAssessment`।

`session` ও `throttle` দুটোই স্টোরেজের জন্য trait অ্যাবস্ট্রাকশন ব্যবহার করে; একাধিক ইনস্ট্যান্সে ডিপ্লয়ের জন্য এই trait প্রয়োগ করে Redis-এ যুক্ত করা যায়।

---

## বাস্তবায়িত ফিচার

### ইনজেকশন-ধরনের আক্রমণ (১১টি ডিটেক্টর)

| ডিটেক্টর | কভার করা প্যাটার্ন | গুরুতরতা |
|--------|---------|--------|
| **xss** | `<script>`, `onerror=` ইত্যাদি ইভেন্ট হ্যান্ডলার, `javascript:` সিউডো-প্রোটোকল, `<svg>`/`<iframe>` ট্যাগ, CSS `expression()`, `eval()`, `document.cookie` | Critical |
| **sql_injection** | `UNION SELECT`, `sleep()`/`benchmark()`/`pg_sleep()` ডিলে ইনজেকশন, `information_schema` এনুমারেশন, `exec sp_`/`xp_` স্টোর্ড প্রসিডিউর, বুলিয়ান ব্লাইন্ড ইনজেকশন প্যাটার্ন `' OR '1'='1`, `LOAD_FILE()`/`INTO OUTFILE` | Critical |
| **command_injection** | ব্যাকটিক কমান্ড, `$()` সাবকমান্ড, পাইপ অপারেটর চেইন এক্সিকিউশন, `/dev/tcp` রিভার্স শেল, `passthru()`/`shell_exec()`/`system()` PHP ফাংশন, `cmd.exe`/`powershell` কল | Critical |
| **nosql_injection** | MongoDB `$ne`/`$gt`/`$regex`/`$where` অপারেটর, `$or` ইনজেকশন, অথেনটিকেশন বাইপাস `{"$gt": ""}` | Critical |
| **ldap_injection** | `(&` `(|` `(!` ফিল্টার অপারেটর, `*(cn=` অ্যাট্রিবিউট এনুমারেশন, `objectClass`/`uid` ইনজেকশন | High |
| **xpath_injection** | `' or '1'='1` বুলিয়ান বাইপাস, `' or true()` ফাংশন ইনজেকশন, `'] | '` নোড ট্রাভার্সাল | High |
| **jndi_injection** | `${jndi:ldap://`, `${lower:j}` অবফাসকেশন, `${upper:j}` অবফাসকেশন, `${::-j}` খালি স্ট্রিং অবফাসকেশন, `${env:}` এনভায়রনমেন্ট ভেরিয়েবল লুকআপ, `${sys:}` সিস্টেম প্রপার্টি | Critical |
| **ssi_injection** | `<!--#exec cmd=` কমান্ড এক্সিকিউশন, `<!--#include file=` ফাইল ইনক্লুশন, `<!--#echo var=` ভেরিয়েবল আউটপুট, `<!--#fsize`/`<!--#flastmod` ফাইল তথ্য | High |
| **graphql_injection** | `__schema`/`__type` ইন্ট্রোস্পেকশন কুয়েরি, ডিপ নেস্টেড DoS (≥৫ লেভেল) | Medium |
| **ssti** | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<%=` `<%@`, Velocity `#set()`, Python MRO `__mro__`/`__subclasses__()` স্যান্ডবক্স এস্কেপ | Critical |
| **format_string** | মেমরি-লেখার `%n` স্পেসিফায়ার (`%n`/`%1$n`/`%hn`/`%ln`), বড়-প্রস্থের কনভার্সন `%123456d`, মেমরি ফাঁসের জন্য `%x`/`%p`/`%s`-এর ঘন পুনরাবৃত্তি | Medium |

### প্রোটোকল ও রিকোয়েস্ট আক্রমণ (১১টি ডিটেক্টর)

| ডিটেক্টর | কভার করা প্যাটার্ন | গুরুতরতা |
|--------|---------|--------|
| **ssrf** | `169.254.169.254` ক্লাউড মেটাডেটা, RFC1918 ইন্টারনাল IP (10.x, 172.16-31.x, 192.168.x), `127.x` loopback, `::1` IPv6 loopback, `0.0.0.0`, `gopher://`/`dict://`/`ftp://`/`file://` বিপজ্জনক প্রোটোকল | Critical |
| **xxe** | `<!ENTITY` এন্টিটি ডিক্লারেশন, `SYSTEM`/`PUBLIC` বাহ্যিক রেফারেন্স, `%` প্যারামিটার এন্টিটি, `<!DOCTYPE` DTD ডিক্লারেশন | Critical |
| **header_injection** | `%0d%0a` URL-এনকোডেড CRLF, `\r\n` র- CRLF ইনজেকশন | High |
| **host_header** | একাধিক Host হেডার ইনজেকশন, `X-Forwarded-Host`/`X-Original-URL`/`X-Rewrite-URL` পয়জনিং, CRLF-সহ Host ক্যারিয়িং | High |
| **request_smuggling** | দ্বৈত `Transfer-Encoding` হেডার, `Content-Length: 0` স্মাগলিং, `\r\n0\r\n` chunked টার্মিনেশন অবফাসকেশন | High |
| **open_redirect** | `//evil.com` প্রোটোকল-রিলেটিভ URL, `javascript:`/`data:text/html` সিউডো-প্রোটোকল জাম্প | Medium |
| **cors** | `Origin: null` বাইপাস, `Access-Control-Allow-Origin: *` + Credentials কম্বিনেশন | Medium |
| **websocket** | `Upgrade: websocket` হ্যান্ডশেক, `Origin: null` ক্রস-অরিজিন WS, `ws://` প্লেইনটেক্সট সংযোগ | High |
| **dns_rebinding** | Host হেডারে `127.x`/`10.x`/`192.168.x`/`172.16-31.x` ইন্টারনাল IP, `localhost`, `::1`, `0.0.0.0` | High |
| **log4shell** | `${lower:j}`/`${upper:j}` অবফাসকেশন, `${::-j}` খালি-স্ট্রিং অবফাসকেশন, নেস্টেড `jndi` লুকআপ, এবং URL-এনকোডেড রূপ `%24%7b...%3a...%7d...ndi` | Critical |
| **hpp** | একই প্যারামিটার key-এর পুনরাবৃত্তি (`a=1&a=2`), এবং একই key-এর জন্য `&` ও `;`-এর মিশ্রণ — Java কন্টেইনারের ম্যাট্রিক্স প্যারামিটার `;jsessionid=` বাদ দিয়ে | Medium |

### ডেটা ও সিরিয়ালাইজেশন আক্রমণ (৭টি ডিটেক্টর)

| ডিটেক্টর | কভার করা প্যাটার্ন | গুরুতরতা |
|--------|---------|--------|
| **deserialization** | PHP `O:সংখ্যা:`/`C:সংখ্যা:` সিরিয়ালাইজড অবজেক্ট, `a:সংখ্যা:{` অ্যারে, `unserialize()` কল, `__wakeup`/`__destruct`/`__toString` ইত্যাদি ম্যাজিক মেথড | Critical |
| **csv_injection** | সারির শুরুতে `=`/`+`/`-`/`@` ফর্মুলা অক্ষর, DDE ডাইনামিক ডেটা এক্সচেঞ্জ, `cmd|` কমান্ড পাইপ, `@SUM()` ফাংশন | Medium |
| **mail_header** | `Bcc:`/`Cc:` ব্লাইন্ড কার্বন কপি ইনজেকশন, `From:` একাধিক প্রেরক, `MIME-Version:`/`Content-Type: multipart` MIME হেডার ইনজেকশন, `boundary=` বাউন্ডারি ম্যানিপুলেশন | Medium |
| **jwt_attack** | `alg: none` খালি অ্যালগরিদম বাইপাস, `kid` পাথ ট্রাভার্সাল ইনজেকশন, খালি সিগনেচার সেগমেন্ট, খালি payload সেগমেন্ট | High |
| **prototype_pollution** | `__proto__`/`constructor.prototype` প্রোটোটাইপ চেইন পলিউশন, `__defineGetter__`/`__defineSetter__`/`__lookupGetter__`/`__lookupSetter__` প্রপার্টি হাইজ্যাকিং | High |
| **formula_injection** | বিপজ্জনক স্প্রেডশিট ফাংশন `HYPERLINK()`/`IMPORTXML()`/`IMPORTDATA()`/`IMPORTRANGE()`/`WEBSERVICE()`/`RTD()`/`EXEC()`, পাইপ + সেল রেফারেন্সের মাধ্যমে ফর্মুলা-ভিত্তিক ডেটা এক্সফিলট্রেশন, `DDE(`, এবং `@` ফাংশন | High |
| **redos** | নেস্টেড কোয়ান্টিফায়ার `(x+)+`/`(x*)*`/`(x{2,})+`, সাধারণ প্রিফিক্সযুক্ত বিকল্প, ক্যারেক্টার-ক্লাস বিকল্পের পুনরাবৃত্তি | Medium |

### ফাইল ও সংবেদনশীল ডেটা (৩টি ডিটেক্টর)

| ডিটেক্টর | কভার করা প্যাটার্ন | গুরুতরতা |
|--------|---------|--------|
| **path_traversal** | `../`/`..\\` ডিরেক্টরি ট্রাভার্সাল, `%2e%2e` URL-এনকোডেড বাইপাস, `php://filter`/`php://input`/`phar://`/`zip://`/`data://`/`expect://`/`glob://` প্রোটোকল র‍্যাপার, `%00` নাল বাইট ট্রাঙ্কেশন | Critical |
| **upload** | `<?php`/`<?=` PHP ট্যাগ, `<%@`/`<%=` ASP ট্যাগ, `eval($_`/`system($_`/`exec($_`/`passthru($_` ব্যাকডোর প্যাটার্ন, `$_GET`/`$_POST`/`$_REQUEST`/`$_SERVER` সুপারগ্লোবাল ভেরিয়েবল, `base64_decode()` এনকোডিং বাইপাস | Critical |
| **data_leak** | ১৬-অঙ্কের ক্রেডিট কার্ড PAN (Visa/MasterCard/AmEx/Discover/JCB/Diners), AWS Access Key `AKIA...`, PEM প্রাইভেট কি হেডার `-----BEGIN`, OpenAI/LLM API Key `sk-...`, ডেটাবেস কানেকশন স্ট্রিং `mongodb://`/`mysql://`/`postgresql://`/`redis://`/`jdbc:`, JWT Token | Critical |

---

## ব্যবহার নির্দেশিকা

শূন্য কনফিগারেশনে ব্যবহারযোগ্য:

```rust
use security_rust::Scanner;

let scanner = Scanner::default();
let results = scanner.scan("<script>alert('xss')</script>");
// [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
```

সম্পূর্ণ API রেফারেন্স (ইনস্টলেশন, সিলেক্টিভ স্ক্যানিং, কাস্টম কনফিগারেশন, গুরুতরতা প্রদর্শন, পারফরম্যান্স) দেখুন [API রেফারেন্স](./API.md)।

---

## ডেভেলপমেন্ট

```bash
# বিল্ড
cargo build --release

# টেস্ট (৩৫৪টি ইউনিট টেস্ট + ১০৮টি ইন্টিগ্রেশন টেস্ট = ৪৬২)
cargo test

# কোড চেক
cargo clippy -- -D warnings
```

---

## ডোনেশন / স্পনসর

যদি এই প্রজেক্টটি আপনার কাজে লাগে, স্বেচ্ছায় ডোনেশন দিয়ে সহায়তা করতে পারেন।

| আলিপে | উইচ্যাট পে |
|--------|---------|
| ![আলিপে](./alipay.png) | ![উইচ্যাট পে](./weixinpay.png) |

### গ্লোবাল ট্রান্সফার (আন্তর্জাতিক রেমিট্যান্স)

【প্রাপকের তথ্য】
- প্রাপকের নাম: WANG KEXUN
- প্রাপকের অ্যাকাউন্ট নম্বর: 881015918251

【প্রাপক ব্যাংক】
- ZA Bank SWIFT Code: AABLHKHHXXX
- ব্যাংকের নাম: ZA Bank Limited
- ব্যাংক কোড: 387
- ব্যাংকের ঠিকানা: Core F, Cyberport 3, 100 Cyberport Road, Hong Kong

【ক্রস-বর্ডার রেমিট্যান্স করেসপন্ডেন্ট ব্যাংক (যদি প্রয়োজন হয়)】

দয়া করে মনে রাখবেন, এটি ক্রস-বর্ডার রেমিট্যান্স করেসপন্ডেন্ট (মধ্যস্থতাকারী) ব্যাংকের তথ্য, প্রাপক ব্যাংকের তথ্য নয়। রেমিট্যান্স ব্যাংককে জিজ্ঞাসা করুন যে ক্রস-বর্ডার রেমিট্যান্স করেসপন্ডেন্ট ব্যাংকের তথ্য প্রদান প্রয়োজন কিনা।

হংকং ডলার, চাইনিজ রেনমিনবি এবং মার্কিন ডলার জমার জন্য করেসপন্ডেন্ট ব্যাংক হল Citibank:
- ব্যাংকের নাম: Citibank N.A. Hong Kong
- SWIFT Code: CITIHKHXXXX
- ব্যাংক কোড: 006
- শাখার নাম: Hong Kong Branch
- শাখা কোড: 391
- ব্যাংকের ঠিকানা: Citibank Tower, Citibank Plaza, 3 Garden Road, Central, Hong Kong

অন্যান্য মুদ্রা জমার জন্য করেসপন্ডেন্ট ব্যাংক হল BNY Mellon:
- ব্যাংকের নাম: THE BANK OF NEW YORK MELLON
- SWIFT Code: IRVTUS3NXXX
- ব্যাংকের ঠিকানা: THE BANK OF NEW YORK MELLON, 240 GREENWICH STREET, NEW YORK, United States

---

## লাইসেন্স

MIT — Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
