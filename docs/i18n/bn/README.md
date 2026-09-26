<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust

**🌐 [中文 (原文)](../../../README.md)**

Rust-এ লেখা একটি আক্রমণ শনাক্তকরণ লাইব্রেরি, যা ৪টি প্রধান বিভাগে ৩২টি ডিটেক্টর কভার করে: ইনজেকশন আক্রমণ, প্রোটোকল আক্রমণ, ডেটা/সিরিয়ালাইজেশন আক্রমণ এবং ফাইল/সংবেদনশীল ডেটা ফাঁস। একমাত্র বাহ্যিক নির্ভরতা `regex`, এবং প্রতিটি ডিটেক্টর সম্পূর্ণ স্ট্রিং স্ক্যানিং। এর পাশাপাশি লাইব্রেরিতে ঐচ্ছিক স্টেটফুল মডিউল (`session` ও `throttle`) এবং ঝুঁকি স্কোরিংয়ের জন্য `score` মডিউল রয়েছে।

প্রজেক্টের পোষা প্রাণী **甲哨 Sentri** ([`pet.svg`](../../pet.svg)) — ৩২টি ডিটেক্টরের জন্য ৩২টি খোলসের প্লেট। সব রিপোর্ট করে, কিছু আটকায় না।

---

## প্রজেক্ট পেট: 甲哨 Sentri

<img src="../../pet.svg" alt="甲哨 Sentri — security-rust প্রজেক্টের পোষা প্রাণী" width="340">

একটি সেন্ট্রি কাঁকড়া, হাতে আতশকাচ আর একটি সাইনবোর্ড। চরিত্রটি সাজসজ্জা নয় — এটি এই লাইব্রেরির ডিজাইন, আঁকা অবস্থায়:

| বৈশিষ্ট্য | কী বোঝায় |
|------|---------|
| খোলসে 4 সারি × 8টি প্লেট | ৩২টি স্টেটলেস ডিটেক্টর; 4 সারি = ইনজেকশন / প্রোটোকল / ডেটা / ফাইল |
| বাঁ দিকের দাঁড়ায় আতশকাচ | **দেখা** — `Detector::detect()` কেবল স্ক্যান করে, মিললে একটি প্রমাণ ফেরত দেয় |
| ডান দিকের দাঁড়ায় সাইনবোর্ড (`已上报` — "রিপোর্ট হয়েছে") | **রিপোর্ট** — `DetectionResult` ফেরত দেয়, এক্সসেপশন ছোড়ে না, কল-চেইন ভাঙে না |
| দাঁড়া কখনো কাউকে চিমটি কাটে না | সিদ্ধান্ত কলারের হাতে; একমাত্র ব্যতিক্রম `SessionGuard`, যা সত্যিই `Block` করে |
| একচোখা লেন্স (মনোকল) | অডিটরের পেশাগত অভ্যাস: প্রতিটি সিদ্ধান্তে `matched_pattern` ও `offset` থাকে, তাই মূল টেক্সটে তার অবস্থানে ফেরানো যায় |
| নেমপ্লেটে `deps: regex ×1` | শূন্য-নির্ভরতার প্রতিশ্রুতি: `[dependencies]`-এ কেবল `regex` থাকবে |

নীতিবাক্য: **সব রিপোর্ট করে, কিছু আটকায় না।**

ছবিটি `include_str!` দিয়ে ক্রেটে এমবেড করা (রানটাইমে কোনো খরচ নেই — ব্যবহার না করলে লিংক হয় না), আর ASCII সংস্করণ সরাসরি টার্মিনাল বা লগে ছাপা যায়:

```rust
println!("{}", security_rust::pet::ASCII);
```

---

## প্রজেক্ট লেআউট

```
security-rust/
├── src/
│   ├── lib.rs              Detector trait (একমাত্র চুক্তি), regex_detect হেল্পার, crate ডকুমেন্টেশন
│   ├── scanner.rs          Scanner / ScannerBuilder: ডিফল্টভাবে সব ৩২টি ডিটেক্টর একত্রিত করে
│   ├── result.rs           DetectionResult / AttackCategory / Severity
│   ├── score.rs            ঝুঁকি স্কোরিং: ওয়েটেড যোগফল + ব্যান্ডিং → RiskAssessment
│   ├── pet.rs              প্রজেক্টের পোষা প্রাণী (NAME / TAGLINE / ASCII / SVG)
│   ├── injection/          ১১টি ইনজেকশন ডিটেক্টর
│   ├── protocol/           ১১টি প্রোটোকল ডিটেক্টর
│   ├── data/               ৭টি ডেটা ডিটেক্টর
│   ├── file/               ৩টি ফাইল ডিটেক্টর
│   ├── session/            SessionGuard + SessionStore (guard / store / geo)
│   └── throttle/           Throttle + ThrottleStore (guard / store)
├── tests/                  ৭টি ইন্টিগ্রেশন স্যুট: সেশন, রেট লিমিট, লাইফসাইকেল, ইনভেরিয়েন্ট, রোবাস্টনেস, এন্ড-টু-এন্ড, মাল্টি-কি রেট লিমিট
├── examples/
│   ├── waf.rs              এন্ড-টু-এন্ড পাইপলাইন (স্ক্যান → রেট লিমিট → সেশন → ব্যবস্থা)
│   └── axum_middleware.rs  axum মিডলওয়্যার ইন্টিগ্রেশন রেফারেন্স
├── docs/
│   ├── API.md              সম্পূর্ণ API রেফারেন্স
│   ├── OWASP-COVERAGE.md   OWASP আক্রমণ শ্রেণির সঙ্গে কভারেজ ম্যাট্রিক্স
│   ├── pet.svg             প্রজেক্টের পোষা প্রাণীর ছবি
│   ├── diagrams/           আর্কিটেকচার / ফিচার / লাইফসাইকেল ডায়াগ্রাম (SVG)
│   ├── i18n/               ১২ ভাষার README ও API ডকুমেন্টেশন
│   └── ...                 ডোনেশন QR কোড, কোড রিভিউ ও টেস্ট রিপোর্ট
└── Cargo.toml              একমাত্র রানটাইম নির্ভরতা: regex
```

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
| ডিটেক্টর বনাম স্টেটফুল মডিউল | আলাদা | `Detector::detect(&str)`-এ কেবল একটি স্ট্রিং ইনপুট, যা "টোকেন + ফিঙ্গারপ্রিন্ট + অবস্থান + সময়" যৌগিক ইনপুট প্রকাশ করতে পারে না; তাই `session` / `throttle` `Scanner`-এর বাইরে আলাদা |
| fail-closed বনাম fail-open | অথেনটিকেশন fail-closed, রেট লিমিট fail-open | সেশনে অনুমোদন মানেই বাইপাস, তাই আটকাতেই হবে; অন্যদিকে রেট লিমিটে সব ব্যবহারকারীকে আটকানো নিজের বিরুদ্ধে DoS, মূল অথেনটিকেশন গেট তখনও আটকায়, আর সিদ্ধান্ত কলারের হাতে |

---

## ডিজাইন আর্কিটেকচার

<img src="../../diagrams/architecture.svg" alt="security-rust আর্কিটেকচার: কলার → ডিটেকশন স্তর → স্কোরিং স্তর → গার্ড স্তর → স্টোরেজ" width="900">

উপর থেকে নিচে পাঁচটি স্তর: **কলার** (WAF / গেটওয়ে / অডিট / CLI) → **ডিটেকশন স্তর** (`Scanner`, যা `Vec<Box<dyn Detector>>` ধারণ করে — ৪টি বিভাগে ৩২টি ডিটেক্টর) → **স্কোরিং স্তর** (`score::assess`) → **গার্ড স্তর** (`SessionGuard` / `Throttle`, প্রতিটি একটি স্টোর trait-এর সঙ্গে আবদ্ধ) → **স্টোরেজ অ্যাবস্ট্রাকশন** (বিল্ট-ইন `MemoryStore`, আর Redis কলার নিজে প্রয়োগ করে)।
*(ডায়াগ্রামের টীকাগুলো চিনা ভাষায়; লেবেলগুলো API নাম।)*

`Detector` trait হলো ডিটেকশন স্তরের একমাত্র চুক্তি: `fn detect(&self, input: &str) -> Option<DetectionResult>`। `session`, `throttle` ও `score` এটি প্রয়োগ করে না — কারণ তাদের ইনপুট একক স্ট্রিং নয় (টোকেন + ফিঙ্গারপ্রিন্ট + অবস্থান + সময়), অথবা তারা কাঁচা ইনপুটের বদলে স্ক্যানের ফলাফল গ্রহণ করে — তাই তারা নিজেরাই উত্তর দেয়, যা নিচে বর্ণিত। ডান দিকের লাল রিটার্ন-পথটি এই লাইব্রেরির সীমানা চিহ্নিত করে: **সিদ্ধান্ত ফেরত যায় কলারের কাছে, সে-ই তা কার্যকর করে**; লাইব্রেরি নিজে অনুরোধ স্পর্শ করে না।

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
- **`throttle`** — রেট লিমিট ও নিষিদ্ধকরণ: স্লাইডিং উইন্ডো + থ্রেশহোল্ড নিষিদ্ধকরণ + অ্যাকাউন্ট লক। এতে রয়েছে `Throttle<S: ThrottleStore>`: `check`/`check_any`/`record_failure`/`record_success`/`reset`/`purge_expired`, এবং এটি ফেরত দেয় `ThrottleDecision { Allow { remaining }, Banned { until }, Unavailable }`। ডিফল্ট: threshold 5, window_secs 60, ban_secs 900। এটি **ইচ্ছাকৃত ব্যতিক্রম**: স্টোর ব্যর্থ হলে এটি `Banned` নয়, `Unavailable` ফেরত দেয় — ব্যাকএন্ড গোলযোগে সব ব্যবহারকারীকে আটকে দেওয়া হলো নিজের বিরুদ্ধে DoS, আর সিদ্ধান্ত কলারের হাতে থাকে। আর `record_failure` ফেরত দেয় `ThrottleOutcome` (`Allow`/`Banned`), `Unavailable` ছাড়া।
- **`score`** — ঝুঁকি স্কোরিং: আলাদা আলাদা নিম্ন-গুরুতার সংকেতকে পরিমেয় মানে সমন্বয় করা, যাতে ফলস-পজিটিভ সীমা টিউন করা যায়। `RiskLevel { None, Low, Medium, High, Critical }`, `RiskAssessment`, এবং `Scanner::assess(&str) -> RiskAssessment`।

`session` ও `throttle` দুটোই স্টোরেজের জন্য trait অ্যাবস্ট্রাকশন ব্যবহার করে; একাধিক ইনস্ট্যান্সে ডিপ্লয়ের জন্য এই trait প্রয়োগ করে Redis-এ যুক্ত করা যায়।

---

## বাস্তবায়িত ফিচার

<img src="../../diagrams/features.svg" alt="security-rust ফিচার: ইনজেকশন ১১, প্রোটোকল ১১, ডেটা ৭, ফাইল ৩, সঙ্গে তিনটি স্টেটফুল মডিউল" width="900">

৩২টি ডিটেক্টর চারটি বিভাগ অনুযায়ী সাজানো, আর `Scanner::default()` দিয়ে শূন্য কনফিগারেশনে সবগুলো চালু; নিচের টেবিলগুলো প্রতিটির কভার করা আক্রমণ প্যাটার্ন ও গুরুতরতা তালিকাভুক্ত করে। গুরুতরতা কেবল একটি হিটের ক্ষতি বোঝায়, আর সমন্বিত সামগ্রিক ঝুঁকি মেলে `Scanner::assess()` থেকে।
*(ডায়াগ্রামের টীকাগুলো চিনা ভাষায়; লেবেলগুলো API নাম।)*

### ইনজেকশন-ধরনের আক্রমণ (১১টি ডিটেক্টর)

| ডিটেক্টর | কভার করা প্যাটার্ন | গুরুতরতা |
|--------|---------|--------|
| **xss** | `<script>`, `onerror=` ইত্যাদি ইভেন্ট হ্যান্ডলার, `javascript:` সিউডো-প্রোটোকল, `<svg>`/`<iframe>` ট্যাগ, CSS `expression()`, `eval()`, `document.cookie` | Critical |
| **sql_injection** | `UNION SELECT`, `sleep()`/`benchmark()`/`pg_sleep()` ডিলে ইনজেকশন, `information_schema` এনুমারেশন, `exec sp_`/`xp_` স্টোর্ড প্রসিডিউর, বুলিয়ান ব্লাইন্ড ইনজেকশন প্যাটার্ন `' OR '1'='1`, `LOAD_FILE()`/`INTO OUTFILE` | Critical |
| **command_injection** | ব্যাকটিক কমান্ড, `$()` সাবকমান্ড, পাইপ অপারেটর চেইন এক্সিকিউশন, `/dev/tcp` রিভার্স শেল, `passthru()`/`shell_exec()`/`system()` PHP ফাংশন, `cmd.exe`/`powershell` কল | Critical |
| **nosql_injection** | MongoDB `$ne`/`$gt`/`$regex`/`$where` অপারেটর, `$or` ইনজেকশন, অথেনটিকেশন বাইপাস `{"$gt": ""}` | Critical |
| **ldap_injection** | `(&` `(\|` `(!` ফিল্টার অপারেটর, `*(cn=` অ্যাট্রিবিউট এনুমারেশন, `objectClass`/`uid` ইনজেকশন | High |
| **xpath_injection** | `' or '1'='1` বুলিয়ান বাইপাস, `' or true()` ফাংশন ইনজেকশন, `'] \| '` নোড ট্রাভার্সাল | High |
| **jndi_injection** | `${jndi:ldap://`, `${lower:j}` অবফাসকেশন, `${upper:j}` অবফাসকেশন, `${::-j}` খালি স্ট্রিং অবফাসকেশন, `${env:}` এনভায়রনমেন্ট ভেরিয়েবল লুকআপ, `${sys:}` সিস্টেম প্রপার্টি | Critical |
| **ssi_injection** | `<!--#exec cmd=` কমান্ড এক্সিকিউশন, `<!--#include file=` ফাইল ইনক্লুশন, `<!--#echo var=` ভেরিয়েবল আউটপুট, `<!--#fsize`/`<!--#flastmod` ফাইল তথ্য | High |
| **graphql_injection** | `__schema`/`__type` ইন্ট্রোস্পেকশন কুয়েরি, ডিপ নেস্টেড DoS (≥৫ লেভেল) | Medium |
| **ssti** | Jinja2 `{{ }}` / FreeMarker `${ }` — **ডেলিমিটারের ভিতরে মূল্যায়ন** (`{{7*7}}`, `${7*7}`, `{{config`, `${T(java.lang.Runtime)}`), ERB `<%=` `<%@`, Velocity `#set()`, Python এস্কেপ চেইন `__mro__`/`__subclasses__()`/`__globals__`/`__builtins__`/`__class__`/`__dict__`; ডেলিমিটার নিজে কোনো সংকেত নয়, তাই `${x}`-এর মতো সাধারণ প্লেসহোল্ডার রিপোর্ট হয় না | Critical |
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
| **cors** | `Access-Control-Allow-Origin: null`, `Origin: null` (স্যান্ডবক্স iframe ও CSWSH-এর প্রামাণ্য সূচক), এবং `Access-Control-Allow-Origin: *` **একসাথে** `Access-Control-Allow-Credentials: true`। আলাদাভাবে দুটিই পাবলিক API ও স্ট্যাটিক রিসোর্সে স্বাভাবিক, রিপোর্ট হয় না | Medium |
| **websocket** | একইসাথে `Origin: null` ও WebSocket আপগ্রেড (CSWSH), `ws://` লুপব্যাক/প্রাইভেট/লিঙ্ক-লোকাল ঠিকানা লক্ষ্য করা (ক্লাউড মেটাডেটা এন্ডপয়েন্ট `169.254.169.254` সহ) | High |
| **dns_rebinding** | Host হেডারে `127.x`/`10.x`/`192.168.x`/`172.16-31.x` ইন্টারনাল IP, `localhost`, `::1`, `0.0.0.0` | High |
| **log4shell** | `${lower:j}`/`${upper:j}` অবফাসকেশন, `${::-j}` খালি-স্ট্রিং অবফাসকেশন, নেস্টেড `jndi` লুকআপ, এবং URL-এনকোডেড রূপ `%24%7b...%3a...%7d...ndi` | Critical |
| **hpp** | একই প্যারামিটার key-এর পুনরাবৃত্তি (`a=1&a=2`), এবং একই key-এর জন্য `&` ও `;`-এর মিশ্রণ — Java কন্টেইনারের ম্যাট্রিক্স প্যারামিটার `;jsessionid=` বাদ দিয়ে | Medium |

### ডেটা ও সিরিয়ালাইজেশন আক্রমণ (৭টি ডিটেক্টর)

| ডিটেক্টর | কভার করা প্যাটার্ন | গুরুতরতা |
|--------|---------|--------|
| **deserialization** | PHP `O:সংখ্যা:`/`C:সংখ্যা:` সিরিয়ালাইজড অবজেক্ট, `a:সংখ্যা:{` অ্যারে, `unserialize()` কল, `__wakeup`/`__destruct`/`__toString` ইত্যাদি ম্যাজিক মেথড | Critical |
| **csv_injection** | সেলের শুরুতে `=`/`+`/`-`/`@` ফর্মুলা অক্ষর (ট্যাব ও ক্যারেজ রিটার্ন **বিভাজক**, ফর্মুলার সূচনা নয়), `,`/`;`/`\t` বিভাজকের পরে সরাসরি `=`, DDE ডাইনামিক ডেটা এক্সচেঞ্জ, `cmd\|` কমান্ড পাইপ, `@SUM()` ফাংশন | Medium |
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

## লাইফসাইকেল

<img src="../../diagrams/lifecycle.svg" alt="security-rust লাইফসাইকেল: স্ক্যান, সেশন, রেট লিমিট" width="900">

তিনটি লাইফসাইকেল আলাদা আলাদাভাবে চলে, তাদের একমাত্র মিলনস্থল কলারের রিকোয়েস্ট হ্যান্ডলার:
*(ডায়াগ্রামের টীকাগুলো চিনা ভাষায়; লেবেলগুলো API নাম।)*

| লাইফসাইকেল | শুরু | শেষ | স্টেট থাকে |
|-----------|-----------|---------|----------------|
| **স্ক্যান** | `Scanner::scan(&str)` | `Vec<DetectionResult>` → `score::assess` → `RiskAssessment` | কিছুই না — স্টেটলেস, প্রতিটি কলে স্বতন্ত্র |
| **সেশন** | `SessionGuard::bind()` একটি `SessionRecord` লেখে | প্রতি রিকোয়েস্টে `verify()` → `SessionVerdict` ⇒ `Allow` / `Challenge` / `Block` | `SessionStore` (বিল্ট-ইন `MemoryStore`) |
| **রেট লিমিট** | `Throttle::check_any(&[keys])` | `Allow{remaining}` / `Banned{until}` / `Unavailable` | `ThrottleStore` (বিল্ট-ইন `MemoryThrottleStore`) |

সহজে ভুল হয় এমন দুটি প্রান্ত:

- **`remaining == 0` মানে এই রিকোয়েস্ট প্রত্যাখ্যান করা উচিত** — কোটা শেষ, "আরেকবার চেষ্টার সুযোগ" নয়। `X-RateLimit-*` লেখার সময় এটা উল্টো করবেন না।
- **স্টোর ব্যর্থতার ব্যবস্থাপনা দুই দিকে উল্টো**: `SessionGuard` fail-closed (`StoreUnavailable` ⇒ `Block`, কখনোই পাস করে না — নইলে আক্রমণকারী ইচ্ছাকৃতভাবে ব্যর্থতা ঘটিয়ে এক গোটা শ্রেণির সিদ্ধান্ত বদলে ফেলতে পারে); অন্যদিকে `Throttle` fail-open (`Unavailable` কলারের হাতে, কারণ ব্যাকএন্ডের গোলযোগে সব ব্যবহারকারীকে আটকে রাখা নিজের বিরুদ্ধে DoS, আর মূল গেট `SessionGuard` তখনও আটকাচ্ছে)। এটি লিখিত ডিজাইন সিদ্ধান্ত, কোনো বাদ পড়া ফলব্যাক নয়।

---

## ব্যবহার নির্দেশিকা

শূন্য কনফিগারেশনে ব্যবহারযোগ্য:

```rust
use security_rust::Scanner;

let scanner = Scanner::default();
let results = scanner.scan("<script>alert('xss')</script>");
// [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
```

ঝুঁকি স্কোরিং হিটের তালিকাকে একটিমাত্র স্তরে সমন্বয় করে, যাতে একাধিক নিম্ন-গুরুতার সংকেত নীরবে উপেক্ষিত না হয়:

```rust
let assessment = scanner.assess("=cmd|' /C calc'!A0 `cat /etc/passwd` ../../../etc/passwd");
// assessment.level   >= RiskLevel::High
// assessment.results >= 3
// assessment.score   — কাঁচা ওয়েটেড স্কোর
```

সম্পূর্ণ API রেফারেন্স (ইনস্টলেশন, সিলেক্টিভ স্ক্যানিং, কাস্টম কনফিগারেশন, ঝুঁকি স্কোরিং, গুরুতরতা প্রদর্শন, সেশন নিরাপত্তা, রেট লিমিট ও নিষিদ্ধকরণ, পারফরম্যান্স) দেখুন [API রেফারেন্স](./API.md)।

### সেশন নিরাপত্তা (`session`)

```rust
use security_rust::session::{Decision, MemoryStore, RequestContext, SessionConfig, SessionGuard};

let guard = SessionGuard::new(MemoryStore::new(), SessionConfig::default());

let login = RequestContext {
    token: "tok-abc",
    subject: "u-1",
    fingerprint: "ip=1.2.3.4|ua=curl",   // ক্লায়েন্ট ফিঙ্গারপ্রিন্ট, লগইনের সময় বাঁধা হয়
    location: Some("CN-BJ"),
    coords: Some((39.9042, 116.4074)),
    signature: None,                      // MAC কলার নিজে ইস্যু করে
    at: None,
};

// লগইন: সেশন তৈরি + ফিঙ্গারপ্রিন্ট বাঁধা + অবস্থান রেকর্ড; ভিন্ন অবস্থান কেবল verdict-কে প্রভাবিত করে, লগইন আটকায় না
guard.bind(&login, 1_700_000_000).unwrap();

// প্রতি রিকোয়েস্টে যাচাই: একই token, ভিন্ন ফিঙ্গারপ্রিন্ট ⇒ ক্লায়েন্ট হাইজ্যাকিং
let verdict = guard.verify(&RequestContext { fingerprint: "ip=5.6.7.8|ua=curl", ..login }, 1_700_000_010);

match verdict.decision {
    Decision::Allow => { /* অনুমোদন */ }
    Decision::Challenge => { /* অনুমোদন, তবে দ্বিতীয় যাচাই দরকার: ভিন্ন অবস্থান, ঘড়ির বিচ্যুতি, অপ্রত্যাশিত স্বাক্ষর */ }
    Decision::Block => { /* প্রত্যাখ্যান */ }
}
```

### রেট লিমিট ও নিষিদ্ধকরণ (`throttle`)

```rust
use security_rust::throttle::{MemoryThrottleStore, Throttle, ThrottleConfig, ThrottleDecision};

let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());
let key = "acct:u-1"; // key কলার তৈরি করে ও নর্মালাইজ করে, কাঁচা ইনপুট সরাসরি key হিসেবে দেওয়া যাবে না
let now = 1_700_000_000;

// প্রকৃত অনুরোধের দুটি মাত্রা: IP ও অ্যাকাউন্ট। check_any একবারেই দুটো জিজ্ঞাসা করে, কঠোরতা অনুযায়ী একত্র করে
match throttle.check_any(&["ip:1.2.3.4", key], now) {
    // remaining লেখা যায় X-RateLimit-*-এ; **remaining == 0 মানে এই রিকোয়েস্ট প্রত্যাখ্যান করা উচিত**
    ThrottleDecision::Allow { remaining } => { /* অবশিষ্ট কোটা remaining */ }
    // now >= until হলেই নিষেধাজ্ঞা উঠে গেছে ধরা হয়
    ThrottleDecision::Banned { until } => { /* নিষিদ্ধ, until-এ ওঠে */ }
    // ব্যাকএন্ড গোলযোগ: এই মডিউল কলারের হয়ে সিদ্ধান্ত নেয় না (অনুমোদন + সতর্কবার্তা দেওয়াই প্রত্যাশিত)
    ThrottleDecision::Unavailable => { /* রেট লিমিট ব্যাকএন্ড unavailable */ }
}

// ব্যর্থ প্রমাণীকরণ রেকর্ড: threshold-এ পৌঁছালেই নিষেধাজ্ঞা। ফেরত দেয় ThrottleOutcome (দুটি অবস্থা),
// স্টোর ব্যর্থতা যায় Err পথে —— কখনো না-চলা Unavailable শাখার জন্য মৃত কোড লিখতে হয় না
let _ = throttle.record_failure(key, now);
```

---

## ডেভেলপমেন্ট

```bash
# বিল্ড
cargo build --release

# টেস্ট (৪৯৪টি: ৩৬৫টি ইউনিট + ১২৮টি ইন্টিগ্রেশন + ১টি ডক টেস্ট)
cargo test

# এন্ড-টু-এন্ড পাইপলাইন উদাহরণ (স্ক্যান → রেট লিমিট → সেশন → ব্যবস্থা)
cargo run --example waf

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
