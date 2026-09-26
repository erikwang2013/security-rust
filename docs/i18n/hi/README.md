<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust

**🌐 [中文 (原文)](../../../README.md)**

Rust में लिखी गई हमले का पता लगाने वाली (attack detection) लाइब्रेरी, जो इंजेक्शन हमलों, प्रोटोकॉल हमलों, डेटा/सीरियलाइज़ेशन हमलों और फ़ाइल/संवेदनशील-डेटा लीक की 4 श्रेणियों में कुल 32 डिटेक्टरों को कवर करती है। एकमात्र बाहरी निर्भरता `regex` है, और हर डिटेक्टर शुद्ध स्ट्रिंग स्कैनिंग है। इसके अतिरिक्त लाइब्रेरी वैकल्पिक स्टेटफुल मॉड्यूल (`session` और `throttle`) तथा जोखिम स्कोरिंग के लिए `score` मॉड्यूल प्रदान करती है।

प्रोजेक्ट का मास्कॉट **甲哨 Sentri** ([`pet.svg`](../../pet.svg)) — 32 कवच प्लेटें, 32 डिटेक्टर। सब कुछ रिपोर्ट करता है, कुछ भी ब्लॉक नहीं करता।

---

## प्रोजेक्ट मास्कॉट: 甲哨 Sentri

<img src="../../pet.svg" alt="甲哨 Sentri — security-rust प्रोजेक्ट का मास्कॉट" width="340">

एक प्रहरी केकड़ा, जिसके एक पंजे में आवर्धक लेंस और दूसरे में तख्ती है। यह पात्र केवल सजावट नहीं है — यह इस लाइब्रेरी का डिज़ाइन ही है, चित्रित रूप में:

| तत्व | यह किसका प्रतीक है |
|---------|---------|
| कवच पर 4 पंक्तियाँ × 8 प्लेटें | 32 स्टेटलेस डिटेक्टर; 4 पंक्तियाँ = इंजेक्शन / प्रोटोकॉल / डेटा / फ़ाइल |
| बाएँ पंजे का आवर्धक लेंस | **देखना** — `Detector::detect()` केवल स्कैन करता है; मिलने पर एक प्रमाण लौटाता है |
| दाएँ पंजे की तख्ती (`已上报` — "रिपोर्ट किया गया") | **रिपोर्ट करना** — `DetectionResult` लौटाता है, कभी अपवाद नहीं फेंकता, कॉल-चेन नहीं तोड़ता |
| पंजे कभी किसी को दबाते नहीं | निर्णय का अधिकार कॉलर के पास है; एकमात्र अपवाद `SessionGuard` है, जो वाकई `Block` करता है |
| मोनोकल | ऑडिटर की आदत: हर निष्कर्ष के साथ `matched_pattern` और `offset` आता है, जो मूल इनपुट में सटीक स्थान बताता है |
| नेमप्लेट पर `deps: regex ×1` | शून्य-निर्भरता का वादा: `[dependencies]` में हमेशा केवल `regex` |

आदर्श वाक्य: **सब कुछ रिपोर्ट करें, कुछ भी ब्लॉक न करें।**

यह चित्र `include_str!` के ज़रिए crate में समाहित है (रनटाइम पर शून्य लागत — उपयोग न करने पर लिंक नहीं होता), और ASCII संस्करण सीधे टर्मिनल या लॉग में भेजा जा सकता है:

```rust
println!("{}", security_rust::pet::ASCII);
```

---

## प्रोजेक्ट संरचना

```
security-rust/
├── src/
│   ├── lib.rs              Detector trait (एकमात्र अनुबंध), regex_detect हेल्पर, crate दस्तावेज़
│   ├── scanner.rs          Scanner / ScannerBuilder: डिफ़ॉल्ट रूप से सभी 32 डिटेक्टर जोड़ता है
│   ├── result.rs           DetectionResult / AttackCategory / Severity
│   ├── score.rs            जोखिम स्कोरिंग: भारित योग + बैंडिंग → RiskAssessment
│   ├── pet.rs              प्रोजेक्ट मास्कॉट (NAME / TAGLINE / ASCII / SVG)
│   ├── injection/          11 इंजेक्शन डिटेक्टर
│   ├── protocol/           11 प्रोटोकॉल डिटेक्टर
│   ├── data/               7 डेटा डिटेक्टर
│   ├── file/               3 फ़ाइल डिटेक्टर
│   ├── session/            SessionGuard + SessionStore (guard / store / geo)
│   └── throttle/           Throttle + ThrottleStore (guard / store)
├── tests/                  7 इंटीग्रेशन सूट: सत्र, दर सीमा, जीवनचक्र, इनवेरिएंट, मज़बूती, एंड-टू-एंड, बहु-कुंजी दर सीमा
├── examples/
│   ├── waf.rs              एंड-टू-एंड पाइपलाइन उदाहरण (स्कैन → दर सीमा → सत्र → कार्रवाई)
│   └── axum_middleware.rs  axum मिडलवेयर एकीकरण संदर्भ
├── docs/
│   ├── API.md              पूर्ण API संदर्भ
│   ├── OWASP-COVERAGE.md   OWASP हमला श्रेणियों के विरुद्ध कवरेज मैट्रिक्स
│   ├── pet.svg             प्रोजेक्ट मास्कॉट का चित्र
│   ├── diagrams/           आर्किटेक्चर / सुविधाएँ / जीवनचक्र आरेख (SVG)
│   ├── i18n/               12 भाषाओं में README और API दस्तावेज़
│   └── ...                 दान QR कोड, कोड-समीक्षा और परीक्षण रिपोर्ट
└── Cargo.toml              एकमात्र रनटाइम निर्भरता: regex
```

---

## डिज़ाइन दर्शन

### "इंटरसेप्ट" के बजाय "पता लगाना" क्यों

यह लाइब्रेरी **शुद्ध इनपुट स्कैनर** के रूप में स्थित है — यह स्ट्रिंग प्राप्त करती है और संरचित पहचान परिणाम लौटाती है। यह किसी भी Web फ्रेमवर्क से बंधी नहीं है, HTTP अनुरोध/प्रतिक्रिया पार्सिंग नहीं करती, और रीयल-टाइम ब्लॉकिंग लागू नहीं करती। इस तरह आप इसे किसी भी चेन में एम्बेड कर सकते हैं: WAF नियम इंजन, लॉग ऑडिट, API गेटवे प्री-वैलिडेशन, CLI सुरक्षा स्कैनिंग टूल आदि।

यह विवरण `Scanner` और `Detector` पर ही लागू होता है। `session` और `throttle` जानबूझकर अपवाद हैं: दोनों **स्टेटफुल और पहचान-केंद्रित** हैं (टोकन + क्लाइंट फ़िंगरप्रिंट + स्थान + समय) — यह एक समग्र इनपुट है जिसे `Detector::detect(&str)` व्यक्त नहीं कर सकता, इसलिए ये मॉड्यूल जानबूझकर इसे लागू नहीं करते।

### आर्किटेक्चर सिद्धांत

- **एकल ज़िम्मेदारी** — हर डिटेक्टर केवल एक प्रकार के हमले से निपटता है, और आंतरिक रूप से संकलित रेगेक्स पैटर्न सेट रखता है
- **एकीकृत इंटरफ़ेस** — `Detector` trait सभी डिटेक्टरों का एकमात्र अनुबंध है: `fn detect(&self, input: &str) -> Option<DetectionResult>`
- **डिफ़ॉल्ट कवरेज** — `Scanner::default()` एक क्लिक में सभी 32 डिटेक्टरों को इकट्ठा करता है, बिना कॉन्फ़िगरेशन के उपयोग योग्य
- **वैकल्पिक कॉन्फ़िगरेशन** — `Scanner::builder()` मांग के अनुसार अनुकूलन का समर्थन करता है, `.with_detector()` के माध्यम से चुनिंदा रूप से डिटेक्टर जोड़ें

### ट्रेड-ऑफ़

| निर्णय | विकल्प | कारण |
|------|------|------|
| रेगेक्स बनाम पार्सर | रेगेक्स | पहचान परिदृश्यों में गति को प्राथमिकता दी जाती है; रेगेक्स विकृत/बाईपास पैटर्न का बेहतर कवरेज देता है |
| पहले-आओ-पहले-रिपोर्ट बनाम पूर्ण पहचान | पूर्ण पहचान | एक इनपुट एक साथ कई प्रकार के हमलों को ट्रिगर कर सकता है; रिपोर्ट में कोई कमी नहीं होनी चाहिए |
| शून्य निर्भरता बनाम serde जोड़ना | शून्य निर्भरता | केवल `regex` पर निर्भर — स्टेटफुल मॉड्यूल भी स्टोरेज को trait के ज़रिए लेते हैं, इसलिए कोई नई निर्भरता नहीं; तेज़ संकलन, छोटा आकार |
| डिटेक्टर बनाम स्टेटफुल मॉड्यूल | अलग | `Detector::detect(&str)` केवल एक स्ट्रिंग लेता है, इसलिए «टोकन + फ़िंगरप्रिंट + स्थान + समय» जैसा समग्र इनपुट व्यक्त नहीं कर सकता; इसीलिए `session` / `throttle` `Scanner` से स्वतंत्र हैं |
| fail-closed बनाम fail-open | प्रमाणीकरण fail-closed, दर सीमा fail-open | सत्र निर्णय को पास करना बाईपास के बराबर है, इसलिए रोकना अनिवार्य है; जबकि दर सीमा में सभी उपयोगकर्ताओं को रोकना स्वयं पर DoS है, और मुख्य प्रमाणीकरण द्वार अब भी रोकता है — निर्णय कॉलर पर छोड़ा जाता है |

---

## डिज़ाइन आर्किटेक्चर

<img src="../../diagrams/architecture.svg" alt="security-rust — आर्किटेक्चर: कॉलर → डिटेक्शन परत → स्कोरिंग परत → गार्ड परत → स्टोरेज" width="900">

पाँच परतें, ऊपर से नीचे: **कॉलर** (WAF / गेटवे / ऑडिट / CLI) → **डिटेक्शन परत** (`Vec<Box<dyn Detector>>` रखने वाला `Scanner`, 4 श्रेणियों में 32 डिटेक्टर) → **स्कोरिंग परत** (`score::assess`) → **गार्ड परत** (`SessionGuard` / `Throttle`, प्रत्येक एक स्टोर trait से बंधा) → **स्टोरेज एब्सट्रैक्शन** (अंतर्निहित `MemoryStore`; Redis कॉलर द्वारा लागू किया जाता है)।
*(आरेख की टिप्पणियाँ चीनी में हैं; लेबल API नाम हैं।)*

`Detector` trait डिटेक्शन परत का एकमात्र अनुबंध है: `fn detect(&self, input: &str) -> Option<DetectionResult>`। `session`, `throttle` और `score` इसे लागू नहीं करते — उनका इनपुट एक अकेली स्ट्रिंग नहीं है (टोकन + फ़िंगरप्रिंट + स्थान + समय), या वे कच्चे इनपुट के बजाय स्कैन परिणामों का उपभोग करते हैं — इसलिए वे स्वयं उत्तर देते हैं, जैसा नीचे दस्तावेज़ित है। दाईं ओर की लाल वापसी-रेखा लाइब्रेरी की सीमा दर्शाती है: **निर्णय निष्पादन के लिए कॉलर को लौटाया जाता है**; लाइब्रेरी स्वयं अनुरोध को कभी नहीं छूती।

### मॉड्यूल ज़िम्मेदारियाँ

| मॉड्यूल | पथ | डिटेक्टरों की संख्या | ज़िम्मेदारी |
|------|------|---------|------|
| कोर | `src/lib.rs` `result.rs` `scanner.rs` | — | `Detector` trait, `DetectionResult`, `Scanner`/`ScannerBuilder` |
| इंजेक्शन | `src/injection/` | 11 | XSS, SQL इंजेक्शन, कमांड इंजेक्शन, NoSQL, LDAP, XPATH, JNDI, SSI, GraphQL, SSTI, फ़ॉर्मेट स्ट्रिंग इंजेक्शन |
| प्रोटोकॉल | `src/protocol/` | 11 | SSRF, XXE, हेडर इंजेक्शन, Host हेडर हमला, अनुरोध स्मगलिंग, ओपन रीडायरेक्ट, CORS, WebSocket, DNS रीबाइंडिंग, Log4Shell, HTTP पैरामीटर प्रदूषण |
| डेटा | `src/data/` | 7 | PHP डिसीरियलाइज़ेशन, CSV फ़ॉर्मूला इंजेक्शन, ईमेल हेडर इंजेक्शन, JWT हमला, प्रोटोटाइप प्रदूषण, स्प्रेडशीट फ़ॉर्मूला इंजेक्शन, ReDoS पहचान |
| फ़ाइल | `src/file/` | 3 | पथ ट्रैवर्सल, दुर्भावनापूर्ण फ़ाइल अपलोड, संवेदनशील डेटा लीक |
| सत्र | `src/session/` | — | `SessionGuard`, `RequestContext`, `SessionVerdict`, `SessionConfig`, `SessionStore` trait + `MemoryStore` |
| दर सीमा | `src/throttle/` | — | `Throttle`, `ThrottleDecision`, `ThrottleConfig`, `ThrottleStore` trait + `MemoryThrottleStore` |
| जोखिम स्कोरिंग | `src/score.rs` | — | `RiskLevel`, `RiskAssessment`, `assess()` |

### पहचान परिणाम संरचना

`DetectionResult` संरचनात्मक रूप से `attack_type`, `category`, `severity`, `matched_pattern`, `offset`, `message` — छह फ़ील्ड लौटाता है। पूर्ण परिभाषा के लिए [API संदर्भ](./API.md) देखें।

### स्टेटफुल मॉड्यूल और जोखिम स्कोरिंग

`session` और `throttle` जानबूझकर `Detector` trait लागू नहीं करते, क्योंकि उनका इनपुट समग्र (composite) है — टोकन + फ़िंगरप्रिंट + स्थान + समय — जिसे `Detector::detect(&str)` व्यक्त नहीं कर सकता। नीचे दिए तीन मॉड्यूल स्ट्रिंग स्कैनिंग के ऊपर की परत बनाते हैं:

- **`session`** — सत्र सुरक्षा: क्लाइंट हाइजैकिंग, डेटा छेड़छाड़, भिन्न स्थान से लॉगिन, टोकन सत्र। इसमें `SessionGuard<S: SessionStore>` है: `bind`/`verify`/`revoke`/`revoke_all`/`rotate`। डिफ़ॉल्ट: `ttl_secs` = 3600, `impossible_travel_kmh` = 900.0, `timestamp_skew_secs` = 300। स्टोर विफल होने पर परिणाम `Decision::Block` होता है (कारण `StoreUnavailable`) — यानी **fail-closed**, पास होने का कोई रास्ता नहीं।
- **`throttle`** — दर सीमा और प्रतिबंध: स्लाइडिंग विंडो + थ्रेशोल्ड प्रतिबंध + खाता लॉक। इसमें `Throttle<S: ThrottleStore>` है: `check`/`check_any`/`record_failure`/`record_success`/`reset`/`purge_expired`, और यह `ThrottleDecision { Allow { remaining }, Banned { until }, Unavailable }` लौटाता है। डिफ़ॉल्ट: threshold 5, window_secs 60, ban_secs 900। यह **जानबूझकर अपवाद** है: स्टोर विफल होने पर यह `Banned` नहीं, `Unavailable` लौटाता है — बैकएंड गड़बड़ी पर सभी उपयोगकर्ताओं को रोकना स्वयं पर DoS है, और निर्णय कॉलर पर छोड़ा जाता है। तथा `record_failure` `ThrottleOutcome` (`Allow`/`Banned`) लौटाता है, `Unavailable` रहित।
- **`score`** — जोखिम स्कोरिंग: अलग-अलग कम-गंभीर संकेतों को मापने योग्य मान में समेटना, ताकि फ़ॉल्स-पॉज़िटिव सीमा को ट्यून किया जा सके। `RiskLevel { None, Low, Medium, High, Critical }`, `RiskAssessment`, और `Scanner::assess(&str) -> RiskAssessment`।

`session` और `throttle` दोनों स्टोरेज के लिए trait एब्सट्रैक्शन का उपयोग करते हैं; कई इंस्टेंस में तैनाती के लिए यह trait लागू करके Redis से जोड़ा जा सकता है।

---

## लागू की गई सुविधाएँ

<img src="../../diagrams/features.svg" alt="security-rust — सुविधाएँ: इंजेक्शन 11, प्रोटोकॉल 11, डेटा 7, फ़ाइल 3, तथा तीन स्टेटफुल मॉड्यूल" width="900">

सभी 32 डिटेक्टर श्रेणी के अनुसार इकट्ठे होते हैं और `Scanner::default()` के ज़रिए बिना किसी कॉन्फ़िगरेशन के डिफ़ॉल्ट रूप से सक्रिय रहते हैं। नीचे दी गई तालिकाएँ बताती हैं कि प्रत्येक डिटेक्टर क्या कवर करता है और उसकी गंभीरता क्या है। गंभीरता एकल हिट का वर्णन करती है; समग्र जोखिम वह है जो `Scanner::assess()` लौटाता है।
*(आरेख की टिप्पणियाँ चीनी में हैं; लेबल API नाम हैं।)*

### इंजेक्शन-प्रकार के हमले (11 डिटेक्टर)

| डिटेक्टर | कवर किए गए पैटर्न | गंभीरता |
|--------|---------|--------|
| **xss** | `<script>`, `onerror=` जैसे इवेंट हैंडलर, `javascript:` छद्म-प्रोटोकॉल, `<svg>`/`<iframe>` टैग, CSS `expression()`, `eval()`, `document.cookie` | Critical |
| **sql_injection** | `UNION SELECT`, `sleep()`/`benchmark()`/`pg_sleep()` विलंब इंजेक्शन, `information_schema` एन्यूमरेशन, `exec sp_`/`xp_` स्टोर्ड प्रोसीजर, बूलियन ब्लाइंड इंजेक्शन पैटर्न `' OR '1'='1`, `LOAD_FILE()`/`INTO OUTFILE` | Critical |
| **command_injection** | बैकटिक कमांड, `$()` सबकमांड, पाइप चेन निष्पादन, `/dev/tcp` रिवर्स शेल, `passthru()`/`shell_exec()`/`system()` PHP फ़ंक्शन, `cmd.exe`/`powershell` कॉल | Critical |
| **nosql_injection** | MongoDB `$ne`/`$gt`/`$regex`/`$where` ऑपरेटर, `$or` इंजेक्शन, ऑथेंटिकेशन बाईपास `{"$gt": ""}` | Critical |
| **ldap_injection** | `(&` `(\|` `(!` फ़िल्टर ऑपरेटर, `*(cn=` एट्रिब्यूट एन्यूमरेशन, `objectClass`/`uid` इंजेक्शन | High |
| **xpath_injection** | `' or '1'='1` बूलियन बाईपास, `' or true()` फ़ंक्शन इंजेक्शन, `'] \| '` नोड ट्रैवर्सल | High |
| **jndi_injection** | `${jndi:ldap://`, `${lower:j}` अस्पष्टता, `${upper:j}` अस्पष्टता, `${::-j}` खाली-स्ट्रिंग अस्पष्टता, `${env:}` एनवायरनमेंट वेरिएबल लुकअप, `${sys:}` सिस्टम प्रॉपर्टी | Critical |
| **ssi_injection** | `<!--#exec cmd=` कमांड निष्पादन, `<!--#include file=` फ़ाइल इंक्लूज़न, `<!--#echo var=` वेरिएबल आउटपुट, `<!--#fsize`/`<!--#flastmod` फ़ाइल जानकारी | High |
| **graphql_injection** | `__schema`/`__type` इंट्रोस्पेक्शन क्वेरी, डीप-नेस्टेड DoS (≥5 परतें) | Medium |
| **ssti** | Jinja2 `{{ }}` / FreeMarker `${ }` — **डिलिमिटर के भीतर मूल्यांकन** (`{{7*7}}`, `${7*7}`, `{{config`, `${T(java.lang.Runtime)}`), ERB `<%=` `<%@`, Velocity `#set()`, Python एस्केप चेन `__mro__`/`__subclasses__()`/`__globals__`/`__builtins__`/`__class__`/`__dict__`; अकेले डिलिमिटर कोई संकेत नहीं हैं, इसलिए `${x}` जैसा सामान्य प्लेसहोल्डर रिपोर्ट नहीं होता | Critical |
| **format_string** | मेमोरी-लेखन `%n` स्पेसिफ़ायर (`%n`/`%1$n`/`%hn`/`%ln`), बड़ी-चौड़ाई कन्वर्ज़न `%123456d`, मेमोरी लीक के लिए `%x`/`%p`/`%s` का सघन दोहराव | Medium |

### प्रोटोकॉल और अनुरोध हमले (11 डिटेक्टर)

| डिटेक्टर | कवर किए गए पैटर्न | गंभीरता |
|--------|---------|--------|
| **ssrf** | `169.254.169.254` क्लाउड मेटाडेटा, RFC1918 इंट्रानेट IP (10.x, 172.16-31.x, 192.168.x), `127.x` loopback, `::1` IPv6 loopback, `0.0.0.0`, `gopher://`/`dict://`/`ftp://`/`file://` खतरनाक प्रोटोकॉल | Critical |
| **xxe** | `<!ENTITY` एंटिटी घोषणा, `SYSTEM`/`PUBLIC` बाहरी संदर्भ, `%` पैरामीटर एंटिटी, `<!DOCTYPE` DTD घोषणा | Critical |
| **header_injection** | `%0d%0a` URL-एन्कोडेड CRLF, `\r\n` रॉ CRLF इंजेक्शन | High |
| **host_header** | एकाधिक Host हेडर इंजेक्शन, `X-Forwarded-Host`/`X-Original-URL`/`X-Rewrite-URL` पॉइज़निंग, CRLF के साथ Host | High |
| **request_smuggling** | दोहरा `Transfer-Encoding` हेडर, `Content-Length: 0` स्मगलिंग, `\r\n0\r\n` chunked टर्मिनेशन अस्पष्टता | High |
| **open_redirect** | `//evil.com` प्रोटोकॉल-रिलेटिव URL, `javascript:`/`data:text/html` छद्म-प्रोटोकॉल रीडायरेक्ट | Medium |
| **cors** | `Access-Control-Allow-Origin: null`, `Origin: null` (सैंडबॉक्स iframe और CSWSH का प्रामाणिक संकेतक), तथा `Access-Control-Allow-Origin: *` **के साथ** `Access-Control-Allow-Credentials: true`। अलग-अलग दोनों सार्वजनिक API और स्टैटिक संसाधनों के लिए सामान्य हैं, रिपोर्ट नहीं होते | Medium |
| **websocket** | `Origin: null` और WebSocket अपग्रेड का साथ-साथ होना (CSWSH), `ws://` का लूपबैक/प्राइवेट/लिंक-लोकल पते पर इंगित होना (क्लाउड मेटाडेटा एंडपॉइंट `169.254.169.254` सहित) | High |
| **dns_rebinding** | Host हेडर में `127.x`/`10.x`/`192.168.x`/`172.16-31.x` इंट्रानेट IP, `localhost`, `::1`, `0.0.0.0` | High |
| **log4shell** | `${lower:j}`/`${upper:j}` अस्पष्टता, `${::-j}` खाली-स्ट्रिंग अस्पष्टता, नेस्टेड `jndi` लुकअप, और URL-एन्कोडेड रूप `%24%7b...%3a...%7d...ndi` | Critical |
| **hpp** | एक ही पैरामीटर key का दोहराव (`a=1&a=2`), तथा उसी key के लिए `&` और `;` का मिश्रण — Java कंटेनर के मैट्रिक्स पैरामीटर `;jsessionid=` को छोड़कर | Medium |

### डेटा और सीरियलाइज़ेशन हमले (7 डिटेक्टर)

| डिटेक्टर | कवर किए गए पैटर्न | गंभीरता |
|--------|---------|--------|
| **deserialization** | PHP `O:अंक:`/`C:अंक:` सीरियलाइज़्ड ऑब्जेक्ट, `a:अंक:{` ऐरे, `unserialize()` कॉल, `__wakeup`/`__destruct`/`__toString` जैसी मैजिक मेथड | Critical |
| **csv_injection** | सेल के आरंभ में `=`/`+`/`-`/`@` फ़ॉर्मूला कैरेक्टर (टैब और कैरिज रिटर्न **विभाजक** हैं, फ़ॉर्मूला की शुरुआत नहीं), `,`/`;`/`\t` विभाजक के तुरंत बाद `=`, DDE डायनामिक डेटा एक्सचेंज, `cmd\|` कमांड पाइप, `@SUM()` फ़ंक्शन | Medium |
| **mail_header** | `Bcc:`/`Cc:` ब्लाइंड कार्बन कॉपी इंजेक्शन, `From:` एकाधिक प्रेषक, `MIME-Version:`/`Content-Type: multipart` MIME हेडर इंजेक्शन, `boundary=` बाउंड्री मैनिपुलेशन | Medium |
| **jwt_attack** | `alg: none` खाली एल्गोरिदम बाईपास, `kid` पथ ट्रैवर्सल इंजेक्शन, खाली सिग्नेचर खंड, खाली payload खंड | High |
| **prototype_pollution** | `__proto__`/`constructor.prototype` प्रोटोटाइप चेन प्रदूषण, `__defineGetter__`/`__defineSetter__`/`__lookupGetter__`/`__lookupSetter__` प्रॉपर्टी हाइजैकिंग | High |
| **formula_injection** | खतरनाक स्प्रेडशीट फ़ंक्शन `HYPERLINK()`/`IMPORTXML()`/`IMPORTDATA()`/`IMPORTRANGE()`/`WEBSERVICE()`/`RTD()`/`EXEC()`, पाइप + सेल संदर्भ के ज़रिए फ़ॉर्मूला-आधारित डेटा एक्सफ़िल्ट्रेशन, `DDE(`, और `@` फ़ंक्शन | High |
| **redos** | नेस्टेड क्वांटिफ़ायर `(x+)+`/`(x*)*`/`(x{2,})+`, साझा उपसर्ग वाले विकल्प, चरित्र-वर्ग विकल्प का दोहराव | Medium |

### फ़ाइल और संवेदनशील डेटा (3 डिटेक्टर)

| डिटेक्टर | कवर किए गए पैटर्न | गंभीरता |
|--------|---------|--------|
| **path_traversal** | `../`/`..\\` डायरेक्टरी ट्रैवर्सल, `%2e%2e` URL-एन्कोडेड बाईपास, `php://filter`/`php://input`/`phar://`/`zip://`/`data://`/`expect://`/`glob://` प्रोटोकॉल रैपर, `%00` नल-बाइट ट्रंकेशन | Critical |
| **upload** | `<?php`/`<?=` PHP टैग, `<%@`/`<%=` ASP टैग, `eval($_`/`system($_`/`exec($_`/`passthru($_` बैकडोर पैटर्न, `$_GET`/`$_POST`/`$_REQUEST`/`$_SERVER` सुपरग्लोबल्स, `base64_decode()` एन्कोडिंग बाईपास | Critical |
| **data_leak** | 16-अंकीय क्रेडिट कार्ड PAN (Visa/MasterCard/AmEx/Discover/JCB/Diners), AWS Access Key `AKIA...`, PEM प्राइवेट की हेडर `-----BEGIN`, OpenAI/LLM API Key `sk-...`, डेटाबेस कनेक्शन स्ट्रिंग `mongodb://`/`mysql://`/`postgresql://`/`redis://`/`jdbc:`, JWT Token | Critical |

---

## जीवनचक्र

<img src="../../diagrams/lifecycle.svg" alt="security-rust — तीन जीवनचक्र: स्कैनिंग, सत्र, दर सीमा" width="900">

तीन जीवनचक्र स्वतंत्र रूप से चलते हैं, और उनका एकमात्र मिलन-स्थल कॉलर का अनुरोध-हैंडलर फ़ंक्शन है:
*(आरेख की टिप्पणियाँ चीनी में हैं; लेबल API नाम हैं।)*

| जीवनचक्र | प्रारंभ | अंत | स्थिति कहाँ रहती है |
|-----------|-----------|---------|----------------|
| **स्कैनिंग** | `Scanner::scan(&str)` | `Vec<DetectionResult>` → `score::assess` → `RiskAssessment` | कुछ नहीं — स्टेटलेस, हर कॉल पर स्वतंत्र |
| **सत्र** | `SessionGuard::bind()` एक `SessionRecord` लिखता है | हर अनुरोध पर `verify()` → `SessionVerdict` ⇒ `Allow` / `Challenge` / `Block` | `SessionStore` (अंतर्निहित `MemoryStore`) |
| **दर सीमा** | `Throttle::check_any(&[keys])` | `Allow{remaining}` / `Banned{until}` / `Unavailable` | `ThrottleStore` (अंतर्निहित `MemoryThrottleStore`) |

दो ऐसी सीमाएँ जहाँ ग़लती आसान है:

- **`remaining == 0` का अर्थ है कि यह अनुरोध अस्वीकार किया जाना चाहिए** — कोटा समाप्त हो चुका है, «एक और प्रयास बाकी» नहीं। `X-RateLimit-*` लिखते समय इसे उल्टा न करें।
- **स्टोर विफलताओं का उपचार विपरीत दिशाओं में होता है**: `SessionGuard` fail-closed है (`StoreUnavailable` ⇒ `Block`, कभी पास नहीं — अन्यथा बैकएंड विफलता भड़काने वाला हमलावर जाँचों की पूरी श्रेणी बदल देता है); `Throttle` fail-open है (`Unavailable` कॉलर को सौंपा जाता है, क्योंकि बैकएंड गड़बड़ी पर सभी उपयोगकर्ताओं को रोकना स्वयं पर DoS है, और मुख्य गेट `SessionGuard` अब भी रोक रहा है)। यह लिखित डिज़ाइन निर्णय है, छूटी हुई सुरक्षा नहीं।

---

## उपयोग गाइड

बिना कॉन्फ़िगरेशन के उपयोग:

```rust
use security_rust::Scanner;

let scanner = Scanner::default();
let results = scanner.scan("<script>alert('xss')</script>");
// [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
```

जोखिम स्कोरिंग हिट सूची को एक ही स्तर में समेटती है, ताकि कई कम-गंभीर संकेत चुपचाप अनदेखे न रहें:

```rust
let assessment = scanner.assess("=cmd|' /C calc'!A0 `cat /etc/passwd` ../../../etc/passwd");
// assessment.level   >= RiskLevel::High
// assessment.results >= 3
// assessment.score   — कच्चा भारित स्कोर
```

पूर्ण API संदर्भ (इंस्टॉलेशन, चयनात्मक स्कैनिंग, कस्टम कॉन्फ़िगरेशन, जोखिम स्कोरिंग, गंभीरता प्रदर्शन, सत्र सुरक्षा, दर सीमा और प्रतिबंध, प्रदर्शन) के लिए [API संदर्भ](./API.md) देखें।

### सत्र सुरक्षा (`session`)

```rust
use security_rust::session::{Decision, MemoryStore, RequestContext, SessionConfig, SessionGuard};

let guard = SessionGuard::new(MemoryStore::new(), SessionConfig::default());

let login = RequestContext {
    token: "tok-abc",
    subject: "u-1",
    fingerprint: "ip=1.2.3.4|ua=curl",   // क्लाइंट फ़िंगरप्रिंट, लॉगिन के समय बंधता है
    location: Some("CN-BJ"),
    coords: Some((39.9042, 116.4074)),
    signature: None,                      // MAC कॉलर द्वारा हस्ताक्षरित
    at: None,
};

// लॉगिन: सत्र बनाएँ + फ़िंगरप्रिंट बाँधें + स्थान दर्ज करें;
// भिन्न स्थान केवल निर्णय पर असर डालता है, लॉगिन नहीं रोकता
guard.bind(&login, 1_700_000_000).unwrap();

// हर अनुरोध पर सत्यापन: वही token, दूसरा फ़िंगरप्रिंट ⇒ क्लाइंट हाइजैकिंग
let verdict = guard.verify(&RequestContext { fingerprint: "ip=5.6.7.8|ua=curl", ..login }, 1_700_000_010);

match verdict.decision {
    Decision::Allow => { /* पास करें */ }
    Decision::Challenge => { /* पास करें पर दूसरा सत्यापन माँगें: भिन्न स्थान, घड़ी का अंतर, अप्रत्याशित हस्ताक्षर */ }
    Decision::Block => { /* अस्वीकार करें */ }
}
```

### दर सीमा और प्रतिबंध (`throttle`)

```rust
use security_rust::throttle::{MemoryThrottleStore, Throttle, ThrottleConfig, ThrottleDecision};

let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());
let key = "acct:u-1"; // key कॉलर बनाता और सामान्यीकृत करता है; कच्चे इनपुट को सीधे key न बनाएँ
let now = 1_700_000_000;

// वास्तविक अनुरोध के दो आयाम हैं: IP और खाता। check_any दोनों एक साथ पूछता है और सबसे कड़े परिणाम पर मिला देता है
match throttle.check_any(&["ip:1.2.3.4", key], now) {
    // remaining को X-RateLimit-* में लिखा जा सकता है; **remaining == 0 का अर्थ है यह अनुरोध अस्वीकार किया जाना चाहिए**
    ThrottleDecision::Allow { remaining } => { /* शेष कोटा: remaining */ }
    // now >= until होते ही प्रतिबंध हटा माना जाता है
    ThrottleDecision::Banned { until } => { /* until तक प्रतिबंधित */ }
    // बैकएंड विफलता: यह मॉड्यूल कॉलर की ओर से निर्णय नहीं लेता (सुझाव: पास करें + चेतावनी दें)
    ThrottleDecision::Unavailable => { /* दर सीमा बैकएंड अनुपलब्ध */ }
}

// प्रमाणीकरण विफलता दर्ज करें: threshold तक पहुँचते ही प्रतिबंध। ThrottleOutcome (दो अवस्थाएँ) लौटाता है,
// और स्टोर विफलता Err बनती है — कभी न चलने वाली Unavailable शाखा के लिए कोड लिखने की ज़रूरत नहीं
let _ = throttle.record_failure(key, now);
```

---

## विकास

```bash
# बिल्ड
cargo build --release

# टेस्ट (494: 365 यूनिट + 128 इंटीग्रेशन + 1 डॉक टेस्ट)
cargo test

# एंड-टू-एंड पाइपलाइन उदाहरण (स्कैन → दर सीमा → सत्र → कार्रवाई)
cargo run --example waf

# कोड चेक
cargo clippy -- -D warnings
```

---

## दान / प्रायोजन

यदि यह प्रोजेक्ट आपके लिए उपयोगी है, तो दान के रूप में समर्थन करने का स्वागत है (स्वैच्छिक)।

| 支付宝 (Alipay) | 微信支付 (WeChat Pay) |
|--------|---------|
| ![支付宝](alipay.png) | ![微信支付](weixinpay.png) |

### वैश्विक स्थानांतरण (अंतर्राष्ट्रीय रेमिटेंस)

【प्राप्तकर्ता जानकारी】
- प्राप्तकर्ता का नाम: WANG KEXUN
- प्राप्तकर्ता खाता संख्या: 881015918251

【प्राप्तकर्ता बैंक】
- ZA Bank SWIFT Code: AABLHKHHXXX
- बैंक का नाम: ZA Bank Limited
- बैंक कोड: 387
- बैंक का पता: Core F, Cyberport 3, 100 Cyberport Road, Hong Kong

【क्रॉस-बॉर्डर रेमिटेंस एजेंट बैंक (यदि आवश्यक हो)】

कृपया ध्यान दें, यह क्रॉस-बॉर्डर रेमिटेंस एजेंट बैंक (मध्यस्थ बैंक) की जानकारी है, प्राप्तकर्ता बैंक की नहीं। कृपया रेमिटिंग बैंक से पूछें कि क्या क्रॉस-बॉर्डर रेमिटेंस एजेंट बैंक की जानकारी प्रदान करना आवश्यक है।

हांगकांग डॉलर, रेनमिन्बी और अमेरिकी डॉलर जमा करने के लिए एजेंट बैंक Citibank है:
- बैंक का नाम: Citibank N.A. Hong Kong
- SWIFT Code: CITIHKHXXXX
- बैंक कोड: 006
- शाखा का नाम: Hong Kong Branch
- शाखा कोड: 391
- बैंक का पता: Citibank Tower, Citibank Plaza, 3 Garden Road, Central, Hong Kong

अन्य मुद्राओं में जमा करने पर एजेंट बैंक BNY Mellon है:
- बैंक का नाम: THE BANK OF NEW YORK MELLON
- SWIFT Code: IRVTUS3NXXX
- बैंक का पता: THE BANK OF NEW YORK MELLON, 240 GREENWICH STREET, NEW YORK, United States

---

## लाइसेंस

MIT — Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
