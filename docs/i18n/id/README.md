<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust

**🌐 [中文 (原文)](../../README.md)**

Pustaka pendeteksi serangan yang ditulis dalam Rust, mencakup 4 kategori utama — serangan injeksi, serangan protokol, serangan data/serialisasi, kebocoran file/data sensitif — dengan total 27 detektor. Tanpa ketergantungan kerangka kerja eksternal, murni pemindaian string.

---

## Filosofi Desain

### Mengapa «Deteksi» dan bukan «Pemblokiran»

Pustaka ini diposisikan sebagai **pemindai input murni** — menerima string, mengembalikan hasil deteksi terstruktur. Tidak terikat pada kerangka kerja web apa pun, tidak melakukan parsing permintaan/respons HTTP, tidak menerapkan pemblokiran real-time. Dengan begitu, Anda dapat menyematkannya ke dalam rantai apa pun: mesin aturan WAF, audit log, validasi awal di depan gateway API, alat pemindaian keamanan CLI, dan lain-lain.

### Prinsip Arsitektur

- **Satu tanggung jawab** — setiap detektor hanya menangani satu jenis serangan, dan di dalamnya menyimpan kumpulan pola regex yang telah dikompilasi
- **Antarmuka terpadu** — trait `Detector` adalah satu-satunya kontrak untuk semua detektor: `fn detect(&self, input: &str) -> Option<DetectionResult>`
- **Cakupan bawaan** — `Scanner::default()` merakit seluruh 27 detektor dalam satu langkah, siap pakai tanpa konfigurasi
- **Konfigurasi opsional** — `Scanner::builder()` mendukung penyesuaian sesuai kebutuhan, merakit detektor secara selektif melalui `.with_detector()`

### Pertimbangan

| Keputusan | Pilihan | Alasan |
|------|------|------|
| Regex vs parser | Regex | Dalam skenario deteksi, kecepatan diutamakan; regex memiliki cakupan yang lebih baik untuk pola terobfuskasi/bypass |
| Laporkan yang pertama vs deteksi penuh | Deteksi penuh | Satu input dapat memicu beberapa jenis serangan sekaligus, sebaiknya tidak ada yang terlewat |
| Nol dependensi vs mengimpor serde | Nol dependensi | Hanya bergantung pada `regex` + `thiserror`, kompilasi cepat, ukuran kecil |

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

### Tanggung Jawab Modul

| Modul | Jalur | Jumlah Detektor | Tanggung Jawab |
|------|------|---------|------|
| Inti | `src/lib.rs` `result.rs` `scanner.rs` | — | trait `Detector`, `DetectionResult`, `Scanner`/`ScannerBuilder` |
| Injeksi | `src/injection/` | 10 | XSS, injeksi SQL, injeksi perintah, NoSQL, LDAP, XPATH, JNDI, SSI, GraphQL, SSTI |
| Protokol | `src/protocol/` | 9 | SSRF, XXE, injeksi header, serangan Host header, penyelundupan permintaan (request smuggling), open redirect, CORS, WebSocket, DNS rebinding |
| Data | `src/data/` | 5 | Deserialisasi PHP, injeksi formula CSV, injeksi header email, serangan JWT, prototype pollution |
| File | `src/file/` | 3 | Path traversal, unggah file berbahaya, kebocoran data sensitif |

### Struktur Hasil Deteksi

`DetectionResult` mengembalikan secara terstruktur enam bidang: `attack_type`, `category`, `severity`, `matched_pattern`, `offset`, `message`. Definisi lengkap lihat [Referensi API](./API.md).

---

## Fitur yang Diimplementasikan

### Serangan Injeksi (10 detektor)

| Detektor | Pola yang Dicakup | Severity |
|--------|---------|--------|
| **xss** | `<script>`, penangan peristiwa seperti `onerror=`, protokol semu `javascript:`, tag `<svg>`/`<iframe>`, CSS `expression()`, `eval()`, `document.cookie` | Critical |
| **sql_injection** | `UNION SELECT`, injeksi penundaan `sleep()`/`benchmark()`/`pg_sleep()`, enumerasi `information_schema`, prosedur tersimpan `exec sp_`/`xp_`, pola boolean blind `' OR '1'='1`, `LOAD_FILE()`/`INTO OUTFILE` | Critical |
| **command_injection** | Perintah backtick, subperintah `$()`, eksekusi berantai melalui pipe, reverse shell `/dev/tcp`, fungsi PHP `passthru()`/`shell_exec()`/`system()`, pemanggilan `cmd.exe`/`powershell` | Critical |
| **nosql_injection** | Operator MongoDB `$ne`/`$gt`/`$regex`/`$where`, injeksi `$or`, bypass autentikasi `{"$gt": ""}` | Critical |
| **ldap_injection** | Operator filter `(&` `(|` `(!`, enumerasi atribut `*(cn=`, injeksi `objectClass`/`uid` | High |
| **xpath_injection** | Bypass boolean `' or '1'='1`, injeksi fungsi `' or true()`, traversal simpul `'] | '` | High |
| **jndi_injection** | `${jndi:ldap://`, obfuscation `${lower:j}`, obfuscation `${upper:j}`, obfuscasi string kosong `${::-j}`, lookup variabel lingkungan `${env:}`, properti sistem `${sys:}` | Critical |
| **ssi_injection** | Eksekusi perintah `<!--#exec cmd=`, inklusi file `<!--#include file=`, output variabel `<!--#echo var=`, info file `<!--#fsize`/`<!--#flastmod` | High |
| **graphql_injection** | Query introspeksi `__schema`/`__type`, DoS bersarang dalam (≥5 lapis) | Medium |
| **ssti** | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<%=` `<%@`, Velocity `#set()`, escape sandbox Python MRO `__mro__`/`__subclasses__()` | Critical |

### Serangan Protokol & Permintaan (9 detektor)

| Detektor | Pola yang Dicakup | Severity |
|--------|---------|--------|
| **ssrf** | Metadata cloud `169.254.169.254`, IP intranet RFC1918 (10.x, 172.16-31.x, 192.168.x), loopback `127.x`, IPv6 loopback `::1`, `0.0.0.0`, protokol berbahaya `gopher://`/`dict://`/`ftp://`/`file://` | Critical |
| **xxe** | Deklarasi entitas `<!ENTITY`, referensi eksternal `SYSTEM`/`PUBLIC`, entitas parameter `%`, deklarasi DTD `<!DOCTYPE` | Critical |
| **header_injection** | CRLF terenkode URL `%0d%0a`, injeksi CRLF mentah `\r\n` | High |
| **host_header** | Injeksi beberapa Host header, poisoning `X-Forwarded-Host`/`X-Original-URL`/`X-Rewrite-URL`, Host dengan CRLF | High |
| **request_smuggling** | Header `Transfer-Encoding` ganda, penyelundupan `Content-Length: 0`, obfuscation terminasi chunked `\r\n0\r\n` | High |
| **open_redirect** | URL relatif protokol `//evil.com`, lompatan protokol semu `javascript:`/`data:text/html` | Medium |
| **cors** | Bypass `Origin: null`, kombinasi `Access-Control-Allow-Origin: *` + Credentials | Medium |
| **websocket** | Handshake `Upgrade: websocket`, WS lintas domain `Origin: null`, koneksi plaintext `ws://` | High |
| **dns_rebinding** | Host header berupa IP intranet `127.x`/`10.x`/`192.168.x`/`172.16-31.x`, `localhost`, `::1`, `0.0.0.0` | High |

### Serangan Data & Serialisasi (5 detektor)

| Detektor | Pola yang Dicakup | Severity |
|--------|---------|--------|
| **deserialization** | Objek serialisasi PHP `O:angka:`/`C:angka:`, array `a:angka:{`, pemanggilan `unserialize()`, metode magic seperti `__wakeup`/`__destruct`/`__toString` | Critical |
| **csv_injection** | Karakter formula di awal baris `=`/`+`/`-`/`@`, DDE dynamic data exchange, pipe perintah `cmd|`, fungsi `@SUM()` | Medium |
| **mail_header** | Injeksi salinan tersembunyi `Bcc:`/`Cc:`, beberapa pengirim `From:`, injeksi header MIME `MIME-Version:`/`Content-Type: multipart`, manipulasi `boundary=` | Medium |
| **jwt_attack** | Bypass algoritma kosong `alg: none`, injeksi path traversal `kid`, segmen tanda tangan kosong, segmen payload kosong | High |
| **prototype_pollution** | Polusi rantai prototipe `__proto__`/`constructor.prototype`, pembajakan properti `__defineGetter__`/`__defineSetter__`/`__lookupGetter__`/`__lookupSetter__` | High |

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

# Tes (46 tes integrasi)
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
