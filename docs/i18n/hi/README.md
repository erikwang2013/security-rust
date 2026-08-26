<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust

**🌐 [中文 (原文)](../../README.md)**

Rust में लिखी गई हमले का पता लगाने वाली (attack detection) लाइब्रेरी, जो इंजेक्शन हमलों, प्रोटोकॉल हमलों, डेटा/सीरियलाइज़ेशन हमलों और फ़ाइल/संवेदनशील-डेटा लीक की 4 श्रेणियों में कुल 27 डिटेक्टरों को कवर करती है। शून्य बाहरी फ्रेमवर्क निर्भरता, शुद्ध स्ट्रिंग स्कैनिंग।

---

## डिज़ाइन दर्शन

### "इंटरसेप्ट" के बजाय "पता लगाना" क्यों

यह लाइब्रेरी **शुद्ध इनपुट स्कैनर** के रूप में स्थित है — यह स्ट्रिंग प्राप्त करती है और संरचित पहचान परिणाम लौटाती है। यह किसी भी Web फ्रेमवर्क से बंधी नहीं है, HTTP अनुरोध/प्रतिक्रिया पार्सिंग नहीं करती, और रीयल-टाइम ब्लॉकिंग लागू नहीं करती। इस तरह आप इसे किसी भी चेन में एम्बेड कर सकते हैं: WAF नियम इंजन, लॉग ऑडिट, API गेटवे प्री-वैलिडेशन, CLI सुरक्षा स्कैनिंग टूल आदि।

### आर्किटेक्चर सिद्धांत

- **एकल ज़िम्मेदारी** — हर डिटेक्टर केवल एक प्रकार के हमले से निपटता है, और आंतरिक रूप से संकलित रेगेक्स पैटर्न सेट रखता है
- **एकीकृत इंटरफ़ेस** — `Detector` trait सभी डिटेक्टरों का एकमात्र अनुबंध है: `fn detect(&self, input: &str) -> Option<DetectionResult>`
- **डिफ़ॉल्ट कवरेज** — `Scanner::default()` एक क्लिक में सभी 27 डिटेक्टरों को इकट्ठा करता है, बिना कॉन्फ़िगरेशन के उपयोग योग्य
- **वैकल्पिक कॉन्फ़िगरेशन** — `Scanner::builder()` मांग के अनुसार अनुकूलन का समर्थन करता है, `.with_detector()` के माध्यम से चुनिंदा रूप से डिटेक्टर जोड़ें

### ट्रेड-ऑफ़

| निर्णय | विकल्प | कारण |
|------|------|------|
| रेगेक्स बनाम पार्सर | रेगेक्स | पहचान परिदृश्यों में गति को प्राथमिकता दी जाती है; रेगेक्स विकृत/बाईपास पैटर्न का बेहतर कवरेज देता है |
| पहले-आओ-पहले-रिपोर्ट बनाम पूर्ण पहचान | पूर्ण पहचान | एक इनपुट एक साथ कई प्रकार के हमलों को ट्रिगर कर सकता है; रिपोर्ट में कोई कमी नहीं होनी चाहिए |
| शून्य निर्भरता बनाम serde जोड़ना | शून्य निर्भरता | केवल `regex` + `thiserror` पर निर्भर; तेज़ संकलन, छोटा आकार |

---

## डिज़ाइन आर्किटेक्चर

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
                       │  │   ├─ ... ×27               │  │
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
  │  10 个  │  │   9 个      │  │ 5 个   │  │  3 个   │
  └─────────┘  └─────────────┘  └────────┘  └─────────┘
```

### मॉड्यूल ज़िम्मेदारियाँ

| मॉड्यूल | पथ | डिटेक्टरों की संख्या | ज़िम्मेदारी |
|------|------|---------|------|
| कोर | `src/lib.rs` `result.rs` `scanner.rs` | — | `Detector` trait, `DetectionResult`, `Scanner`/`ScannerBuilder` |
| इंजेक्शन | `src/injection/` | 10 | XSS, SQL इंजेक्शन, कमांड इंजेक्शन, NoSQL, LDAP, XPATH, JNDI, SSI, GraphQL, SSTI |
| प्रोटोकॉल | `src/protocol/` | 9 | SSRF, XXE, हेडर इंजेक्शन, Host हेडर हमला, अनुरोध स्मगलिंग, ओपन रीडायरेक्ट, CORS, WebSocket, DNS रीबाइंडिंग |
| डेटा | `src/data/` | 5 | PHP डिसीरियलाइज़ेशन, CSV फ़ॉर्मूला इंजेक्शन, ईमेल हेडर इंजेक्शन, JWT हमला, प्रोटोटाइप प्रदूषण |
| फ़ाइल | `src/file/` | 3 | पथ ट्रैवर्सल, दुर्भावनापूर्ण फ़ाइल अपलोड, संवेदनशील डेटा लीक |

### पहचान परिणाम संरचना

`DetectionResult` संरचनात्मक रूप से `attack_type`, `category`, `severity`, `matched_pattern`, `offset`, `message` — छह फ़ील्ड लौटाता है। पूर्ण परिभाषा के लिए [API संदर्भ](./API.md) देखें।

---

## लागू की गई सुविधाएँ

### इंजेक्शन-प्रकार के हमले (10 डिटेक्टर)

| डिटेक्टर | कवर किए गए पैटर्न | गंभीरता |
|--------|---------|--------|
| **xss** | `<script>`, `onerror=` जैसे इवेंट हैंडलर, `javascript:` छद्म-प्रोटोकॉल, `<svg>`/`<iframe>` टैग, CSS `expression()`, `eval()`, `document.cookie` | Critical |
| **sql_injection** | `UNION SELECT`, `sleep()`/`benchmark()`/`pg_sleep()` विलंब इंजेक्शन, `information_schema` एन्यूमरेशन, `exec sp_`/`xp_` स्टोर्ड प्रोसीजर, बूलियन ब्लाइंड इंजेक्शन पैटर्न `' OR '1'='1`, `LOAD_FILE()`/`INTO OUTFILE` | Critical |
| **command_injection** | बैकटिक कमांड, `$()` सबकमांड, पाइप चेन निष्पादन, `/dev/tcp` रिवर्स शेल, `passthru()`/`shell_exec()`/`system()` PHP फ़ंक्शन, `cmd.exe`/`powershell` कॉल | Critical |
| **nosql_injection** | MongoDB `$ne`/`$gt`/`$regex`/`$where` ऑपरेटर, `$or` इंजेक्शन, ऑथेंटिकेशन बाईपास `{"$gt": ""}` | Critical |
| **ldap_injection** | `(&` `(|` `(!` फ़िल्टर ऑपरेटर, `*(cn=` एट्रिब्यूट एन्यूमरेशन, `objectClass`/`uid` इंजेक्शन | High |
| **xpath_injection** | `' or '1'='1` बूलियन बाईपास, `' or true()` फ़ंक्शन इंजेक्शन, `'] | '` नोड ट्रैवर्सल | High |
| **jndi_injection** | `${jndi:ldap://`, `${lower:j}` अस्पष्टता, `${upper:j}` अस्पष्टता, `${::-j}` खाली-स्ट्रिंग अस्पष्टता, `${env:}` एनवायरनमेंट वेरिएबल लुकअप, `${sys:}` सिस्टम प्रॉपर्टी | Critical |
| **ssi_injection** | `<!--#exec cmd=` कमांड निष्पादन, `<!--#include file=` फ़ाइल इंक्लूज़न, `<!--#echo var=` वेरिएबल आउटपुट, `<!--#fsize`/`<!--#flastmod` फ़ाइल जानकारी | High |
| **graphql_injection** | `__schema`/`__type` इंट्रोस्पेक्शन क्वेरी, डीप-नेस्टेड DoS (≥5 परतें) | Medium |
| **ssti** | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<%=` `<%@`, Velocity `#set()`, Python MRO `__mro__`/`__subclasses__()` सैंडबॉक्स एस्केप | Critical |

### प्रोटोकॉल और अनुरोध हमले (9 डिटेक्टर)

| डिटेक्टर | कवर किए गए पैटर्न | गंभीरता |
|--------|---------|--------|
| **ssrf** | `169.254.169.254` क्लाउड मेटाडेटा, RFC1918 इंट्रानेट IP (10.x, 172.16-31.x, 192.168.x), `127.x` loopback, `::1` IPv6 loopback, `0.0.0.0`, `gopher://`/`dict://`/`ftp://`/`file://` खतरनाक प्रोटोकॉल | Critical |
| **xxe** | `<!ENTITY` एंटिटी घोषणा, `SYSTEM`/`PUBLIC` बाहरी संदर्भ, `%` पैरामीटर एंटिटी, `<!DOCTYPE` DTD घोषणा | Critical |
| **header_injection** | `%0d%0a` URL-एन्कोडेड CRLF, `\r\n` रॉ CRLF इंजेक्शन | High |
| **host_header** | एकाधिक Host हेडर इंजेक्शन, `X-Forwarded-Host`/`X-Original-URL`/`X-Rewrite-URL` पॉइज़निंग, CRLF के साथ Host | High |
| **request_smuggling** | दोहरा `Transfer-Encoding` हेडर, `Content-Length: 0` स्मगलिंग, `\r\n0\r\n` chunked टर्मिनेशन अस्पष्टता | High |
| **open_redirect** | `//evil.com` प्रोटोकॉल-रिलेटिव URL, `javascript:`/`data:text/html` छद्म-प्रोटोकॉल रीडायरेक्ट | Medium |
| **cors** | `Origin: null` बाईपास, `Access-Control-Allow-Origin: *` + Credentials संयोजन | Medium |
| **websocket** | `Upgrade: websocket` हैंडशेक, `Origin: null` क्रॉस-डोमेन WS, `ws://` प्लेनटेक्स्ट कनेक्शन | High |
| **dns_rebinding** | Host हेडर में `127.x`/`10.x`/`192.168.x`/`172.16-31.x` इंट्रानेट IP, `localhost`, `::1`, `0.0.0.0` | High |

### डेटा और सीरियलाइज़ेशन हमले (5 डिटेक्टर)

| डिटेक्टर | कवर किए गए पैटर्न | गंभीरता |
|--------|---------|--------|
| **deserialization** | PHP `O:अंक:`/`C:अंक:` सीरियलाइज़्ड ऑब्जेक्ट, `a:अंक:{` ऐरे, `unserialize()` कॉल, `__wakeup`/`__destruct`/`__toString` जैसी मैजिक मेथड | Critical |
| **csv_injection** | पंक्ति की शुरुआत में `=`/`+`/`-`/`@` फ़ॉर्मूला कैरेक्टर, DDE डायनामिक डेटा एक्सचेंज, `cmd|` कमांड पाइप, `@SUM()` फ़ंक्शन | Medium |
| **mail_header** | `Bcc:`/`Cc:` ब्लाइंड कार्बन कॉपी इंजेक्शन, `From:` एकाधिक प्रेषक, `MIME-Version:`/`Content-Type: multipart` MIME हेडर इंजेक्शन, `boundary=` बाउंड्री मैनिपुलेशन | Medium |
| **jwt_attack** | `alg: none` खाली एल्गोरिदम बाईपास, `kid` पथ ट्रैवर्सल इंजेक्शन, खाली सिग्नेचर खंड, खाली payload खंड | High |
| **prototype_pollution** | `__proto__`/`constructor.prototype` प्रोटोटाइप चेन प्रदूषण, `__defineGetter__`/`__defineSetter__`/`__lookupGetter__`/`__lookupSetter__` प्रॉपर्टी हाइजैकिंग | High |

### फ़ाइल और संवेदनशील डेटा (3 डिटेक्टर)

| डिटेक्टर | कवर किए गए पैटर्न | गंभीरता |
|--------|---------|--------|
| **path_traversal** | `../`/`..\\` डायरेक्टरी ट्रैवर्सल, `%2e%2e` URL-एन्कोडेड बाईपास, `php://filter`/`php://input`/`phar://`/`zip://`/`data://`/`expect://`/`glob://` प्रोटोकॉल रैपर, `%00` नल-बाइट ट्रंकेशन | Critical |
| **upload** | `<?php`/`<?=` PHP टैग, `<%@`/`<%=` ASP टैग, `eval($_`/`system($_`/`exec($_`/`passthru($_` बैकडोर पैटर्न, `$_GET`/`$_POST`/`$_REQUEST`/`$_SERVER` सुपरग्लोबल्स, `base64_decode()` एन्कोडिंग बाईपास | Critical |
| **data_leak** | 16-अंकीय क्रेडिट कार्ड PAN (Visa/MasterCard/AmEx/Discover/JCB/Diners), AWS Access Key `AKIA...`, PEM प्राइवेट की हेडर `-----BEGIN`, OpenAI/LLM API Key `sk-...`, डेटाबेस कनेक्शन स्ट्रिंग `mongodb://`/`mysql://`/`postgresql://`/`redis://`/`jdbc:`, JWT Token | Critical |

---

## उपयोग गाइड

बिना कॉन्फ़िगरेशन के उपयोग:

```rust
use security_rust::Scanner;

let scanner = Scanner::default();
let results = scanner.scan("<script>alert('xss')</script>");
// [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
```

पूर्ण API संदर्भ (इंस्टॉलेशन, चयनात्मक स्कैनिंग, कस्टम कॉन्फ़िगरेशन, गंभीरता प्रदर्शन, प्रदर्शन) के लिए [API संदर्भ](./API.md) देखें।

---

## विकास

```bash
# बिल्ड
cargo build --release

# टेस्ट (46 इंटीग्रेशन टेस्ट)
cargo test

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
