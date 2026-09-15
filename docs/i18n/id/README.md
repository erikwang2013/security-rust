<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust

**🌐 [中文 (原文)](../../README.md)**

Pustaka pendeteksi serangan yang ditulis dalam Rust, mencakup 4 kategori utama — serangan injeksi, serangan protokol, serangan data/serialisasi, kebocoran file/data sensitif — dengan total 32 detektor. Satu-satunya dependensi eksternal adalah `regex`, dan setiap detektor murni pemindaian string. Selain itu pustaka ini menyediakan modul stateful opsional (`session` dan `throttle`) serta modul `score` untuk penilaian risiko.

---

## Filosofi Desain

### Mengapa «Deteksi» dan bukan «Pemblokiran»

Pustaka ini diposisikan sebagai **pemindai input murni** — menerima string, mengembalikan hasil deteksi terstruktur. Tidak terikat pada kerangka kerja web apa pun, tidak melakukan parsing permintaan/respons HTTP, tidak menerapkan pemblokiran real-time. Dengan begitu, Anda dapat menyematkannya ke dalam rantai apa pun: mesin aturan WAF, audit log, validasi awal di depan gateway API, alat pemindaian keamanan CLI, dan lain-lain.

Pernyataan ini hanya berlaku untuk `Scanner` dan `Detector`. `session` dan `throttle` sengaja menjadi pengecualian: keduanya **stateful dan berpusat pada identitas** (token + fingerprint klien + lokasi + waktu) — input majemuk yang tidak dapat diungkapkan oleh `Detector::detect(&str)`, sehingga kedua modul ini sengaja tidak mengimplementasikannya.

### Prinsip Arsitektur

- **Satu tanggung jawab** — setiap detektor hanya menangani satu jenis serangan, dan di dalamnya menyimpan kumpulan pola regex yang telah dikompilasi
- **Antarmuka terpadu** — trait `Detector` adalah satu-satunya kontrak untuk semua detektor: `fn detect(&self, input: &str) -> Option<DetectionResult>`
- **Cakupan bawaan** — `Scanner::default()` merakit seluruh 32 detektor dalam satu langkah, siap pakai tanpa konfigurasi
- **Konfigurasi opsional** — `Scanner::builder()` mendukung penyesuaian sesuai kebutuhan, merakit detektor secara selektif melalui `.with_detector()`

### Pertimbangan

| Keputusan | Pilihan | Alasan |
|------|------|------|
| Regex vs parser | Regex | Dalam skenario deteksi, kecepatan diutamakan; regex memiliki cakupan yang lebih baik untuk pola terobfuskasi/bypass |
| Laporkan yang pertama vs deteksi penuh | Deteksi penuh | Satu input dapat memicu beberapa jenis serangan sekaligus, sebaiknya tidak ada yang terlewat |
| Nol dependensi vs mengimpor serde | Nol dependensi | Hanya bergantung pada `regex` — modul stateful pun menerima penyimpanan melalui trait, jadi tidak ada dependensi baru; kompilasi cepat, ukuran kecil |

---

## Arsitektur Desain

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

### Tanggung Jawab Modul

| Modul | Jalur | Jumlah Detektor | Tanggung Jawab |
|------|------|---------|------|
| Inti | `src/lib.rs` `result.rs` `scanner.rs` | — | trait `Detector`, `DetectionResult`, `Scanner`/`ScannerBuilder` |
| Injeksi | `src/injection/` | 11 | XSS, injeksi SQL, injeksi perintah, NoSQL, LDAP, XPATH, JNDI, SSI, GraphQL, SSTI, injeksi format string |
| Protokol | `src/protocol/` | 11 | SSRF, XXE, injeksi header, serangan Host header, penyelundupan permintaan (request smuggling), open redirect, CORS, WebSocket, DNS rebinding, Log4Shell, pencemaran parameter HTTP |
| Data | `src/data/` | 7 | Deserialisasi PHP, injeksi formula CSV, injeksi header email, serangan JWT, prototype pollution, injeksi formula spreadsheet, deteksi ReDoS |
| File | `src/file/` | 3 | Path traversal, unggah file berbahaya, kebocoran data sensitif |
| Sesi | `src/session/` | — | `SessionGuard`, `RequestContext`, `SessionVerdict`, `SessionConfig`, trait `SessionStore` + `MemoryStore` |
| Pembatasan laju | `src/throttle/` | — | `Throttle`, `ThrottleDecision`, `ThrottleConfig`, trait `ThrottleStore` + `MemoryThrottleStore` |
| Penilaian risiko | `src/score.rs` | — | `RiskLevel`, `RiskAssessment`, `assess()` |

### Struktur Hasil Deteksi

`DetectionResult` mengembalikan secara terstruktur enam bidang: `attack_type`, `category`, `severity`, `matched_pattern`, `offset`, `message`. Definisi lengkap lihat [Referensi API](./API.md).

### Modul Stateful dan Penilaian Risiko

`session` dan `throttle` sengaja tidak mengimplementasikan trait `Detector`, karena inputnya majemuk — token + fingerprint + lokasi + waktu — yang tidak dapat diungkapkan oleh `Detector::detect(&str)`. Tiga modul berikut membentuk lapisan di atas pemindaian string:

- **`session`** — keamanan sesi: pembajakan klien, perusakan data, login dari lokasi berbeda, sesi token. Menyediakan `SessionGuard<S: SessionStore>`: `bind`/`verify`/`revoke`/`revoke_all`/`rotate`. Default: `ttl_secs` = 3600, `impossible_travel_kmh` = 900.0, `timestamp_skew_secs` = 300. Saat penyimpanan gagal, hasilnya `Decision::Block` (sebab `StoreUnavailable`) — jadi **fail-closed**, tidak ada jalur yang meloloskan.
- **`throttle`** — pembatasan laju dan pemblokiran: sliding window + pemblokiran ambang + penguncian akun. `Throttle<S: ThrottleStore>`: `check`/`record_failure`/`record_success`/`reset`/`purge_expired`, dan mengembalikan `ThrottleDecision { Allow { remaining }, Banned { until }, Unavailable }`. Default: threshold 5, window_secs 60, ban_secs 900. Ini **pengecualian yang disengaja**: saat penyimpanan gagal ia mengembalikan `Unavailable`, bukan `Banned` — memblokir semua pengguna karena gangguan backend adalah DoS terhadap diri sendiri, dan keputusannya diserahkan ke pemanggil.
- **`score`** — penilaian risiko: menggabungkan sinyal berisiko rendah yang terpisah menjadi besaran terukur, agar ambang positif palsu dapat disetel. `RiskLevel { None, Low, Medium, High, Critical }`, `RiskAssessment`, dan `Scanner::assess(&str) -> RiskAssessment`.

`session` dan `throttle` keduanya memakai abstraksi trait untuk penyimpanan; untuk deployment multi-instans, implementasikan trait tersebut untuk terhubung ke Redis.

---

## Fitur yang Diimplementasikan

### Serangan Injeksi (11 detektor)

| Detektor | Pola yang Dicakup | Severity |
|--------|---------|--------|
| **xss** | `<script>`, penangan peristiwa seperti `onerror=`, protokol semu `javascript:`, tag `<svg>`/`<iframe>`, CSS `expression()`, `eval()`, `document.cookie` | Critical |
| **sql_injection** | `UNION SELECT`, injeksi penundaan `sleep()`/`benchmark()`/`pg_sleep()`, enumerasi `information_schema`, prosedur tersimpan `exec sp_`/`xp_`, pola boolean blind `' OR '1'='1`, `LOAD_FILE()`/`INTO OUTFILE` | Critical |
| **command_injection** | Perintah backtick, subperintah `$()`, eksekusi berantai melalui pipe, reverse shell `/dev/tcp`, fungsi PHP `passthru()`/`shell_exec()`/`system()`, pemanggilan `cmd.exe`/`powershell` | Critical |
| **nosql_injection** | Operator MongoDB `$ne`/`$gt`/`$regex`/`$where`, injeksi `$or`, bypass autentikasi `{"$gt": ""}` | Critical |
| **ldap_injection** | Operator filter `(&` `(\|` `(!`, enumerasi atribut `*(cn=`, injeksi `objectClass`/`uid` | High |
| **xpath_injection** | Bypass boolean `' or '1'='1`, injeksi fungsi `' or true()`, traversal simpul `'] \| '` | High |
| **jndi_injection** | `${jndi:ldap://`, obfuscation `${lower:j}`, obfuscation `${upper:j}`, obfuscasi string kosong `${::-j}`, lookup variabel lingkungan `${env:}`, properti sistem `${sys:}` | Critical |
| **ssi_injection** | Eksekusi perintah `<!--#exec cmd=`, inklusi file `<!--#include file=`, output variabel `<!--#echo var=`, info file `<!--#fsize`/`<!--#flastmod` | High |
| **graphql_injection** | Query introspeksi `__schema`/`__type`, DoS bersarang dalam (≥5 lapis) | Medium |
| **ssti** | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<%=` `<%@`, Velocity `#set()`, escape sandbox Python MRO `__mro__`/`__subclasses__()` | Critical |
| **format_string** | Spesifier `%n` penulis memori (`%n`/`%1$n`/`%hn`/`%ln`), konversi lebar besar `%123456d`, pengulangan rapat `%x`/`%p`/`%s` untuk kebocoran memori | Medium |

### Serangan Protokol & Permintaan (11 detektor)

| Detektor | Pola yang Dicakup | Severity |
|--------|---------|--------|
| **ssrf** | Metadata cloud `169.254.169.254`, IP intranet RFC1918 (10.x, 172.16-31.x, 192.168.x), loopback `127.x`, IPv6 loopback `::1`, `0.0.0.0`, protokol berbahaya `gopher://`/`dict://`/`ftp://`/`file://` | Critical |
| **xxe** | Deklarasi entitas `<!ENTITY`, referensi eksternal `SYSTEM`/`PUBLIC`, entitas parameter `%`, deklarasi DTD `<!DOCTYPE` | Critical |
| **header_injection** | CRLF terenkode URL `%0d%0a`, injeksi CRLF mentah `\r\n` | High |
| **host_header** | Injeksi beberapa Host header, poisoning `X-Forwarded-Host`/`X-Original-URL`/`X-Rewrite-URL`, Host dengan CRLF | High |
| **request_smuggling** | Header `Transfer-Encoding` ganda, penyelundupan `Content-Length: 0`, obfuscation terminasi chunked `\r\n0\r\n` | High |
| **open_redirect** | URL relatif protokol `//evil.com`, lompatan protokol semu `javascript:`/`data:text/html` | Medium |
| **cors** | Bypass `Origin: null`, kombinasi `Access-Control-Allow-Origin: *` + Credentials | Medium |
| **websocket** | `Origin: null` bersamaan dengan upgrade WebSocket (CSWSH), `ws://` menuju alamat loopback/pribadi/link-local (termasuk endpoint metadata cloud `169.254.169.254`) | High |
| **dns_rebinding** | Host header berupa IP intranet `127.x`/`10.x`/`192.168.x`/`172.16-31.x`, `localhost`, `::1`, `0.0.0.0` | High |
| **log4shell** | Obfuskasi `${lower:j}`/`${upper:j}`, obfuskasi string kosong `${::-j}`, lookup `jndi` bersarang, dan bentuk terenkode URL `%24%7b...%3a...%7d...ndi` | Critical |
| **hpp** | Pengulangan key parameter yang sama (`a=1&a=2`), serta campuran `&` dan `;` untuk key yang sama — mengecualikan `;jsessionid=` untuk parameter matriks kontainer Java | Medium |

### Serangan Data & Serialisasi (7 detektor)

| Detektor | Pola yang Dicakup | Severity |
|--------|---------|--------|
| **deserialization** | Objek serialisasi PHP `O:angka:`/`C:angka:`, array `a:angka:{`, pemanggilan `unserialize()`, metode magic seperti `__wakeup`/`__destruct`/`__toString` | Critical |
| **csv_injection** | Karakter formula di awal baris `=`/`+`/`-`/`@`, DDE dynamic data exchange, pipe perintah `cmd\|`, fungsi `@SUM()` | Medium |
| **mail_header** | Injeksi salinan tersembunyi `Bcc:`/`Cc:`, beberapa pengirim `From:`, injeksi header MIME `MIME-Version:`/`Content-Type: multipart`, manipulasi `boundary=` | Medium |
| **jwt_attack** | Bypass algoritma kosong `alg: none`, injeksi path traversal `kid`, segmen tanda tangan kosong, segmen payload kosong | High |
| **prototype_pollution** | Polusi rantai prototipe `__proto__`/`constructor.prototype`, pembajakan properti `__defineGetter__`/`__defineSetter__`/`__lookupGetter__`/`__lookupSetter__` | High |
| **formula_injection** | Fungsi spreadsheet berbahaya `HYPERLINK()`/`IMPORTXML()`/`IMPORTDATA()`/`IMPORTRANGE()`/`WEBSERVICE()`/`RTD()`/`EXEC()`, eksfiltrasi data berbasis formula melalui pipe + referensi sel, `DDE(`, dan fungsi `@` | High |
| **redos** | Kuantifier bersarang `(x+)+`/`(x*)*`/`(x{2,})+`, alternasi berprefiks sama, pengulangan alternasi kelas karakter | Medium |

### File & Data Sensitif (3 detektor)

| Detektor | Pola yang Dicakup | Severity |
|--------|---------|--------|
| **path_traversal** | Traversal direktori `../`/`..\\`, bypass terenkode URL `%2e%2e`, pembungkus protokol `php://filter`/`php://input`/`phar://`/`zip://`/`data://`/`expect://`/`glob://`, truncation null byte `%00` | Critical |
| **upload** | Tag PHP `<?php`/`<?=`, tag ASP `<%@`/`<%=`, pola backdoor `eval($_`/`system($_`/`exec($_`/`passthru($_`, superglobal `$_GET`/`$_POST`/`$_REQUEST`/`$_SERVER`, bypass enkode `base64_decode()` | Critical |
| **data_leak** | PAN kartu kredit 16 digit (Visa/MasterCard/AmEx/Discover/JCB/Diners), AWS Access Key `AKIA...`, header kunci privat PEM `-----BEGIN`, API Key OpenAI/LLM `sk-...`, string koneksi database `mongodb://`/`mysql://`/`postgresql://`/`redis://`/`jdbc:`, JWT Token | Critical |

---

## Cara Penggunaan

Siap pakai tanpa konfigurasi:

```rust
use security_rust::Scanner;

let scanner = Scanner::default();
let results = scanner.scan("<script>alert('xss')</script>");
// [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
```

Referensi API lengkap (instalasi, pemindaian selektif, konfigurasi kustom, tampilan severity, performa) lihat [Referensi API](./API.md).

---

## Pengembangan

```bash
# Build
cargo build --release

# Tes (354 tes unit + 108 tes integrasi = 462)
cargo test

# Lint kode
cargo clippy -- -D warnings
```

---

## Donasi / Sponsor

Jika proyek ini bermanfaat bagi Anda, dipersilakan untuk mendukung dengan donasi (sukarela).

| Alipay | WeChat Pay |
|--------|---------|
| ![Alipay](./alipay.png) | ![WeChat Pay](./weixinpay.png) |

### Transfer Global (Remitansi Internasional)

【Informasi Penerima】
- Nama penerima: WANG KEXUN
- Nomor rekening penerima: 881015918251

【Bank Penerima】
- ZA Bank SWIFT Code: AABLHKHHXXX
- Nama bank: ZA Bank Limited
- Kode bank: 387
- Alamat bank: Core F, Cyberport 3, 100 Cyberport Road, Hong Kong

【Bank Koresponden Remitansi Lintas Batas (jika diperlukan)】

Harap diperhatikan, ini adalah informasi bank koresponden remitansi lintas batas (bank perantara), bukan bank penerima. Silakan tanyakan kepada bank pengirim apakah informasi bank koresponden remitansi lintas batas diperlukan.

Bank koresponden untuk penerimaan HKD, CNY, dan USD adalah Citibank:
- Nama bank: Citibank N.A. Hong Kong
- SWIFT Code: CITIHKHXXXX
- Kode bank: 006
- Nama cabang: Hong Kong Branch
- Nomor cabang: 391
- Alamat bank: Citibank Tower, Citibank Plaza, 3 Garden Road, Central, Hong Kong

Bank koresponden untuk penerimaan mata uang lainnya adalah BNY Mellon:
- Nama bank: THE BANK OF NEW YORK MELLON
- SWIFT Code: IRVTUS3NXXX
- Alamat bank: THE BANK OF NEW YORK MELLON, 240 GREENWICH STREET, NEW YORK, United States

---

## Lisensi

MIT — Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
