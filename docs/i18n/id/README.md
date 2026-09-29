<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust

**🌐 [中文 (原文)](../../../README.md)**

Pustaka pendeteksi serangan yang ditulis dalam Rust, mencakup 4 kategori utama — serangan injeksi, serangan protokol, serangan data/serialisasi, kebocoran file/data sensitif — dengan total 32 detektor. Satu-satunya dependensi eksternal adalah `regex`, dan setiap detektor murni pemindaian string. Selain itu pustaka ini menyediakan modul stateful opsional (`session` dan `throttle`) serta modul `score` untuk penilaian risiko.

Maskot proyek, **甲哨 Sentri** ([`pet.svg`](../../pet.svg)) — 32 lempeng cangkang untuk 32 detektor. Laporkan semuanya, jangan blokir apa pun.

---

## Maskot Proyek: 甲哨 Sentri

<img src="../../pet.svg" alt="甲哨 Sentri — maskot proyek security-rust" width="340">

Kepiting penjaga yang memegang kaca pembesar dan papan tanda. Karakternya bukan hiasan — ia adalah desain pustaka ini, yang digambar:

| Elemen | Apa yang dipetakannya |
|---------|---------|
| 4 baris × 8 lempeng cangkang | 32 detektor stateless; 4 baris itu adalah injeksi / protokol / data / file |
| Kaca pembesar di capit kiri | **Melihat** — `Detector::detect()` hanya memindai; satu temuan mengembalikan satu bukti |
| Papan tanda di capit kanan (`已上报` — "dilaporkan") | **Melaporkan** — mengembalikan `DetectionResult`, tidak pernah melempar, tidak pernah memutus rantai pemanggilan |
| Capit yang tidak pernah mencubit | Keputusan ada pada pemanggil; satu-satunya pengecualian adalah `SessionGuard`, yang benar-benar melakukan `Block` |
| Monokel | Kebiasaan auditor: setiap temuan membawa `matched_pattern` dan `offset`, yang menunjuk balik ke posisi di input asli |
| `deps: regex ×1` pada plat nama | Janji nol dependensi: `[dependencies]` selamanya hanya `regex` |

Moto: **laporkan semuanya, jangan blokir apa pun.**

Gambar ini dibundel ke dalam crate dengan `include_str!` (tanpa biaya runtime — tidak ditautkan jika tidak dipakai), dan versi ASCII-nya bisa langsung dicetak ke terminal atau log:

```rust
println!("{}", security_rust::pet::ASCII);
```

---

## Struktur Proyek

```
security-rust/
├── src/
│   ├── lib.rs              trait Detector (satu-satunya kontrak), helper regex_detect, dokumen crate
│   ├── scanner.rs          Scanner / ScannerBuilder: merakit seluruh 32 detektor secara bawaan
│   ├── result.rs           DetectionResult / AttackCategory / Severity
│   ├── score.rs            Penilaian risiko: jumlah berbobot + pengelompokan → RiskAssessment
│   ├── pet.rs              Maskot proyek (NAME / TAGLINE / ASCII / SVG)
│   ├── injection/          11 detektor injeksi
│   ├── protocol/           11 detektor protokol
│   ├── data/               7 detektor data
│   ├── file/               3 detektor file
│   ├── session/            SessionGuard + SessionStore (guard / store / geo)
│   └── throttle/           Throttle + ThrottleStore (guard / store)
├── tests/                  7 suite integrasi: sesi, pembatasan laju, siklus hidup, invarian, ketangguhan, end-to-end, pembatasan multi-kunci
├── examples/
│   ├── waf.rs              Contoh pipeline end-to-end (pemindaian → pembatasan laju → sesi → tindakan)
│   └── axum_middleware.rs  Referensi integrasi middleware axum
├── docs/
│   ├── API.md              Referensi API lengkap
│   ├── OWASP-COVERAGE.md   Matriks cakupan terhadap kelas serangan OWASP
│   ├── pet.svg             Gambar maskot proyek
│   ├── diagrams/           Diagram arsitektur / fitur / siklus hidup (SVG)
│   ├── i18n/               README dan dokumen API dalam 12 bahasa
│   └── ...                 Kode QR donasi, laporan tinjauan kode dan pengujian
└── Cargo.toml              Satu-satunya dependensi runtime: regex
```

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
| Detektor vs modul stateful | Dipisahkan | `Detector::detect(&str)` hanya menerima satu string, sehingga tidak dapat mengungkapkan input majemuk «token + fingerprint + lokasi + waktu»; karena itu `session` / `throttle` berdiri terpisah dari `Scanner` |
| fail-closed vs fail-open | Autentikasi fail-closed, pembatasan laju fail-open | Meloloskan keputusan sesi sama dengan dibobol, jadi harus diblokir; sedangkan memblokir semua pengguna pada pembatasan laju adalah DoS terhadap diri sendiri, dan gerbang autentikasi utama tetap menahan — keputusannya diserahkan ke pemanggil |

### Dua Tingkat: Sinyal Kuat dan Sinyal Lemah

Detektor **tidak** melaporkan setiap temuan pada severity yang dideklarasikannya. 18 dari 32 detektor membagi polanya menjadi dua tingkat (static `STRONG_PATTERNS` / `WEAK_PATTERNS` di dalam sumber):

| Tingkat | Kriteria | Severity yang dilaporkan | Satu temuan bisa melewati garis tolak? |
|------|------|-----------|------------------|
| **Kuat** | Bentuknya sendiri hanya mungkin berasal dari serangan | Tingkat yang dideklarasikan detektor | Bisa |
| **Lemah** | Token itu hanya *muncul* — ada di mana-mana dalam konten normal | Selalu `Severity::Low` (5 poin) | **Tidak** |

Kedua tingkat melewati detektor yang sama dan `attack_type` yang sama; hanya `severity` yang berbeda. Sinyal lemah **tetap terdeteksi** — tidak ada yang dibuang diam-diam: terlihat di `scan()` dan tetap terakumulasi di `assess()`.

Konsekuensi langsungnya bagi pemanggil: **satu sinyal lemah bukan alasan untuk menolak.** Garis tolak pipeline rujukan ([`examples/waf.rs:166`](../../../examples/waf.rs)) adalah `risk.level >= RiskLevel::High` (40 poin), sedangkan satu sinyal lemah hanya 5 poin sehingga tidak masuk ke cabang itu. Untuk melihat serangan di balik sinyal lemah, lihat skor yang dihasilkan `assess()` setelah temuan dari beberapa detektor bertumpuk:

```rust
let scanner = Scanner::default();

// Ketiganya sinyal lemah di tiga detektor berbeda — hanya tumpukannya yang naik tingkat
let a = scanner.assess("<script src=\"/app.js\"></script>\n../config\n__proto__");
// a.results == 3, a.score == 15 (3 × Low) → RiskLevel::Medium
// masih di bawah High; temuan lain di permintaan yang sama akan melewatinya
```

Pola yang diturunkan menjadi sinyal lemah adalah token yang «kemunculannya normal»:

| Sinyal lemah | Mengapa tidak bisa menolak sendiri |
|--------|-------------------|
| `<script src=...>`, `<iframe>`, `<link>`, `expression(` | Ada di setiap halaman web |
| `../` satu tingkat | Path relatif di setiap berkas sumber |
| `-2`, `+1` di awal baris | Butir daftar Markdown, bilangan negatif dalam prosa |
| `__proto__` telanjang (pembacaan prototipe) | JS apa pun yang menyentuh rantai prototipe |
| `${env:}` / `${sys:}` | Sintaks konfigurasi log4j2 yang sah |
| `X-Forwarded-Host`, `X-Original-URL` | Reverse proxy sendiri yang menambahkannya |
| `Host: 10.244.1.5`, `Host: localhost` | Panggilan antar-pod k8s, pengembangan lokal |
| `10.0.0.5`, `192.168.1.1`, `127.0.0.1` telanjang | `X-Forwarded-For`, `bind 127.0.0.1` |
| URL relatif protokol `//evil.com` | Komentar sumber, tautan CDN di dokumentasi |
| `information_schema` | Log galat PG, tutorial SQL |

Tabel di atas hanyalah contoh. Kriterianya adalah **bentuk**, bukan nama berkas: untuk `../` yang sama, satu tingkat (`../x`) adalah sinyal lemah sedangkan banyak tingkat (`../../`) adalah sinyal kuat ([`src/file/path_traversal.rs`](../../../src/file/path_traversal.rs)). Daftar lengkapnya ada di `WEAK_PATTERNS` tiap detektor dan penanda `lemah` di tabel-tabel berikutnya.

---

## Arsitektur Desain

<img src="../../diagrams/architecture.svg" alt="security-rust — arsitektur: pemanggil → lapisan deteksi → lapisan penilaian → lapisan penjaga → penyimpanan" width="900">

Lima lapisan, dari atas ke bawah: **pemanggil** (WAF / gateway / audit / CLI) → **lapisan deteksi** (`Scanner` yang memegang `Vec<Box<dyn Detector>>`, 32 detektor dalam 4 kategori) → **lapisan penilaian** (`score::assess`) → **lapisan penjaga** (`SessionGuard` / `Throttle`, masing-masing terikat pada trait penyimpanan) → **abstraksi penyimpanan** (`MemoryStore` bawaan; Redis diimplementasikan oleh pemanggil).
*(Anotasi diagram dalam bahasa Mandarin; labelnya adalah nama API.)*

Trait `Detector` adalah satu-satunya kontrak lapisan deteksi: `fn detect(&self, input: &str) -> Option<DetectionResult>`. `session`, `throttle`, dan `score` tidak mengimplementasikannya — inputnya bukan satu string tunggal (token + fingerprint + lokasi + waktu), atau modul-modul ini mengonsumsi hasil pemindaian alih-alih input mentah — sehingga masing-masing menjawab sendiri, seperti didokumentasikan di bawah. Jejak balik merah di sebelah kanan menandai batas pustaka: **verdict dikembalikan ke pemanggil untuk dieksekusi**; pustaka tidak pernah menyentuh permintaan itu sendiri.

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
- **`throttle`** — pembatasan laju dan pemblokiran: sliding window + pemblokiran ambang + penguncian akun. `Throttle<S: ThrottleStore>`: `check`/`check_any`/`record_failure`/`record_success`/`reset`/`purge_expired`, dan mengembalikan `ThrottleDecision { Allow { remaining }, Banned { until }, Unavailable }`. Default: threshold 5, window_secs 60, ban_secs 900. Ini **pengecualian yang disengaja**: saat penyimpanan gagal ia mengembalikan `Unavailable`, bukan `Banned` — memblokir semua pengguna karena gangguan backend adalah DoS terhadap diri sendiri, dan keputusannya diserahkan ke pemanggil. `record_failure` mengembalikan `ThrottleOutcome` (`Allow`/`Banned`), tanpa `Unavailable`.
- **`score`** — penilaian risiko: menggabungkan sinyal berisiko rendah yang terpisah menjadi besaran terukur, agar ambang positif palsu dapat disetel. `RiskLevel { None, Low, Medium, High, Critical }`, `RiskAssessment`, dan `Scanner::assess(&str) -> RiskAssessment`.

`session` dan `throttle` keduanya memakai abstraksi trait untuk penyimpanan; untuk deployment multi-instans, implementasikan trait tersebut untuk terhubung ke Redis.

---

## Fitur yang Diimplementasikan

<img src="../../diagrams/features.svg" alt="security-rust — fitur: injeksi 11, protokol 11, data 7, file 3, plus tiga modul stateful" width="900">

Seluruh 32 detektor dirakit per kategori dan diaktifkan secara bawaan melalui `Scanner::default()` tanpa konfigurasi. Tabel di bawah mencantumkan cakupan masing-masing beserta tingkat severity-nya. Severity menggambarkan satu temuan; risiko agregat adalah yang dikembalikan oleh `Scanner::assess()`.
*(Anotasi diagram dalam bahasa Mandarin; labelnya adalah nama API.)*

Pola yang ditandai `lemah` di dalam tabel termasuk **sinyal lemah**: melaporkan `Severity::Low` (5 poin) dan tidak dapat melewati garis tolak sendirian (lihat bagian sebelumnya). Kolom «Severity» adalah **batas atas** yang dapat dicapai detektor itu; detektor yang memiliki penanda `lemah` tetap memiliki kedua tingkat, dan bagian atasnya tetap melaporkan tingkat yang dideklarasikan. Detektor yang seluruhnya lemah (`dns_rebinding`) memiliki batas atas `Low`.

### Serangan Injeksi (11 detektor)

| Detektor | Pola yang Dicakup | Severity |
|--------|---------|--------|
| **xss** | Seluruh tabel penangan peristiwa seperti `onerror=`/`onload=`, protokol semu `javascript:`/`vbscript:` (hanya scheme yang langsung diikuti non-spasi); `lemah`: tag `<script src=...>`/`<iframe>`/`<embed>`/`<object>`/`<link>`, CSS `expression(` | Critical |
| **sql_injection** | `UNION SELECT`, injeksi penundaan `sleep()`/`benchmark()`/`pg_sleep()` (hanya pada posisi pernyataan), prosedur tersimpan `exec sp_`/`xp_`, pola boolean blind `' OR '1'='1`, `LOAD_FILE()`/`INTO OUTFILE`, `DROP TABLE`/`INSERT INTO`, pemisahan komentar `UN/**/ION`; `lemah`: kemunculan kata `information_schema` | Critical |
| **command_injection** | Reverse shell `/dev/tcp`, bentuk pemanggilan `passthru()`/`shell_exec()`/`system("…")`/`popen()`/`pcntl_exec()`, bentuk pemanggilan `powershell -Command`/`cmd.exe /c`; `lemah`: span backtick, subperintah `$()`, eksekusi berantai pipe/`\|\|`/`&&`, `exec(`, `>/dev/null`, pola reader+lokasi seperti `cat /etc/passwd`, kata telanjang `cmd.exe`/`powershell` | Critical |
| **nosql_injection** | Operator MongoDB `$ne`/`$gt`/`$regex`/`$where`, injeksi `$or`, bypass autentikasi `{"$gt": ""}` | Critical |
| **ldap_injection** | Operator filter `(&` `(\|` `(!`, enumerasi atribut `*(cn=`, injeksi `objectClass`/`uid` | High |
| **xpath_injection** | Bypass boolean `' or '1'='1`, injeksi fungsi `' or true()`, traversal simpul `'] \| '` | High |
| **jndi_injection** | Badan lookup `${jndi:`, pelipatan huruf `${lower:j}`/`${upper:j}`, pelipatan string kosong `${::-j}` (ada hanya untuk mengaburkan `jndi`); `lemah`: sintaks lookup yang sah `${env:}`/`${sys:}`/`${java:}` | Critical |
| **ssi_injection** | Eksekusi perintah `<!--#exec cmd=`, inklusi `<!--#include file=` dengan path absolut atau `..`, ekspor variabel lingkungan `<!--#printenv`; `lemah`: output variabel `<!--#echo var=`, info file `<!--#fsize`/`<!--#flastmod`, `<!--#config`, inklusi rutin seperti `<!--#include file="header.html"` | High |
| **graphql_injection** | Query introspeksi dalam bentuk kuery, `__schema {`/`__type {` (menyebut nama bidang dalam prosa tidak dilaporkan); `lemah`: `__typename` (Apollo/Relay menambahkannya ke setiap kuery), kurung kurawal bersarang ≥5 lapis | Medium |
| **ssti** | Jinja2 `{{ }}` / FreeMarker `${ }` — **evaluasi di dalam delimiter** (`{{7*7}}`, `${7*7}`, `{{config`, `${T(java.lang.Runtime)}`, `${@Type@method}`), LFI template melalui `{% include '/…'` / `..`, rantai escape di dalam delimiter `__mro__`/`__subclasses__()`/`__globals__`/`__builtins__`/`__class__`/`__dict__`, FreeMarker `?new(`; `lemah`: direktif template telanjang `{% %}`/`<%=`/`<%@`/`#set(`, atribut magis telanjang; delimiter saja bukan sinyal, placeholder biasa seperti `${x}` tidak dilaporkan | Critical |
| **format_string** | Spesifier `%n` penulis memori (`%n`/`%1$n`/`%hn`/`%ln`), konversi lebar besar `%123456d`, pengulangan rapat `%x`/`%p`/`%s` untuk kebocoran memori | Medium |

### Serangan Protokol & Permintaan (11 detektor)

| Detektor | Pola yang Dicakup | Severity |
|--------|---------|--------|
| **ssrf** | Metadata cloud `169.254.169.254` dan `metadata.google.internal` (tidak menuntut konteks URL), IP intranet di **posisi authority URL** (setelah `//`) `10.x`/`172.16-31.x`/`192.168.x`/`127.x`, `//localhost`, `//0.0.0.0`, `//[::1]`, protokol berbahaya `gopher://`/`dict://`/`ftp://user@`/`file:///`; `lemah`: literal intranet yang sama di **posisi non-URL** (`X-Forwarded-For: 10.0.0.5`, `bind 127.0.0.1`, `{"host": "10.0.0.1"}` identik byte per byte) | Critical |
| **xxe** | Deklarasi entitas `<!ENTITY`, referensi eksternal `SYSTEM`/`PUBLIC`, entitas parameter `%`, deklarasi DTD `<!DOCTYPE` | Critical |
| **header_injection** | `\r\n` sebelum header khusus respons: `Set-Cookie`/`Location`/`Refresh`/`Status`/`WWW-Authenticate`, atau `%0d` bersamaan dengan `%0a` (termasuk urutan terbalik `%0a…%0d`). `Content-Length`/`Content-Type`/`Transfer-Encoding` adalah header **permintaan**, identik byte per byte dengan header pesan yang normal, sehingga bukan lagi sinyal (bentuk terenkode `%0d%0aContent-Length:` tetap ditangkap oleh `%0d`+`%0a`) | High |
| **host_header** | **Dua** header `Host:` (RFC 7230 §5.4 mewajibkan 400, dua lapis parser berbeda pendapat); `lemah`: `X-Forwarded-Host`/`X-Original-URL`/`X-Rewrite-URL` — proxy sendiri juga menambahkannya, identik byte per byte dengan pemalsuan klien (`X-Forwarded-For`/`X-Forwarded-Proto` tidak dilaporkan) | High |
| **request_smuggling** | Header `Transfer-Encoding` ganda, penyelundupan `Content-Length: 0`, obfuscation terminasi chunked `\r\n0\r\n` | High |
| **open_redirect** | Lompatan protokol semu `javascript:`/`data:text/html`/`data:text/plain` (menuntut isi setelah scheme); `lemah`: URL relatif protokol `//evil.com` — identik dengan tautan CDN di komentar sumber dan dokumentasi | Medium |
| **cors** | `Access-Control-Allow-Origin: null`, dan `Access-Control-Allow-Origin: *` **bersamaan dengan** `Access-Control-Allow-Credentials: true`; `lemah`: `Origin: null` di sisi permintaan (iframe sandbox, URL `data:`, dan berkas lokal memiliki origin `null`; baru berlaku jika server memantulkannya dengan `ACAO: null`). Masing-masing sendirian normal untuk API publik dan aset statis dan tidak dilaporkan | Medium |
| **websocket** | `Origin: null` bersamaan dengan upgrade WebSocket (CSWSH), `ws://` menuju alamat loopback/pribadi/link-local (termasuk endpoint metadata cloud `169.254.169.254`) | High |
| **dns_rebinding** | Host header berupa IP intranet `127.x`/`10.x`/`192.168.x`/`172.16-31.x`, `localhost`, `[::1]`, `0.0.0.0`. **Seluruh detektor hanya memiliki tingkat lemah**: selalu melaporkan `Low` (lihat «Batas yang Diketahui») | Low |
| **log4shell** | Obfuskasi `${lower:j}`/`${upper:j}`, obfuskasi string kosong `${::-j}`, lookup `jndi` bersarang, dan bentuk terenkode URL `%24%7b...%3a...%7d...ndi` | Critical |
| **hpp** | Campuran pemisah `&` dan `;` (`?a=1&b=2;c=3`, dua lapis parser menghasilkan jumlah parameter berbeda); `lemah`: pengulangan key yang sama (`?id=1&id=2`) — identik byte per byte dengan parameter multinilai yang sah seperti `?tag=rust&tag=web`; `;jsessionid=` sebagai parameter matriks adalah pemisah path sehingga dikecualikan | Medium |

### Serangan Data & Serialisasi (7 detektor)

| Detektor | Pola yang Dicakup | Severity |
|--------|---------|--------|
| **deserialization** | Objek serialisasi PHP `O:angka:`/`C:angka:`, array `a:angka:{`, pemanggilan `unserialize()`, metode magic dalam **bentuk pemanggilan** (`__wakeup(`/`__destruct(`/`__construct(`/`__toString(`/`__get(`/`__set(`/`__call(`); `lemah`: nama metode magic telanjang (dokumentasi yang membahasnya juga terkena) | Critical |
| **csv_injection** | `=` tepat setelah pemisah `,`/`;`/`\t` yang langsung diikuti non-spasi (formula di sel kedua baris TSV/CSV), `DDE` di awal baris, `cmd\|` di awal baris, `@SUM(` di awal baris; `lemah`: `=`/`+`/`-` di awal baris yang diikuti bukan spasi dan bukan simbol sefamili (`- item` butir daftar, `---` garis pemisah, `++i`, `= 5` tidak terkena). `@` dikeluarkan seluruhnya dari tingkat kasar (`@media`/`@import` ada di mana-mana dalam stylesheet) — hanya `@SUM(` yang tersisa. Tab dan carriage return adalah **pemisah**, bukan awal formula | Medium |
| **mail_header** | Dua header `From:` yang bersebelahan, `MIME-Version:` di awal baris (nama yang tidak ada di tabel field HTTP); `lemah`: `Cc:`/`Bcc:` di awal baris — identik byte per byte dengan surel yang diteruskan dan badan pesan yang disantap sistem tiket. `Content-Type: multipart` dan `boundary=` **dihapus** (`Content-Type: multipart/form-data` adalah header standar setiap POST unggah berkas). Batas atasnya Medium (15 poin): **tidak dapat melewati garis tolak sendirian** | Medium |
| **jwt_attack** | Bypass algoritma kosong `alg: none`, injeksi path traversal `kid`, segmen tanda tangan kosong, segmen payload kosong | High |
| **prototype_pollution** | `__proto__` sebagai key atau sasaran penetapan (`"__proto__":`, `[__proto__]`, `__proto__ = x`), `constructor.prototype`/`constructor[`, `__defineGetter__`/`__defineSetter__`/`__lookupGetter__`/`__lookupSetter__`, `hasOwnProperty[`; `lemah`: `__proto__` telanjang (`obj.__proto__` memang cara bahasa ini membaca prototipe) | High |
| **formula_injection** | Fungsi spreadsheet berbahaya `HYPERLINK()`/`IMPORTXML()`/`IMPORTDATA()`/`IMPORTRANGE()`/`WEBSERVICE()`/`RTD()`/`EXEC()`, eksfiltrasi data berbasis formula melalui pipe + referensi sel, `DDE(`, dan fungsi `@` | High |
| **redos** | Kuantifier bersarang `(x+)+`/`(x*)*`/`(x{2,})+`, alternasi berprefiks sama, pengulangan alternasi kelas karakter | Medium |

### File & Data Sensitif (3 detektor)

| Detektor | Pola yang Dicakup | Severity |
|--------|---------|--------|
| **path_traversal** | Traversal **banyak tingkat** `(?:\.\./){2,}`/`(?:\.\.\\){2,}`, bypass terenkode URL `%2e%2e`/`..%2f`/`..%5c`, pembungkus protokol `php://filter`/`php://input`/`phar://`/`zip://`/`data://`/`expect://`/`glob://`, truncation null byte `%00`; `lemah`: `../`/`..\` satu tingkat (identik dengan path relatif di sumber atau dokumentasi) | Critical |
| **upload** | Tag PHP `<?php`/`<?=`, tag ASP `<%@`/`<%=`, pola backdoor `eval($_`/`system($_`/`exec($_`/`passthru($_`, superglobal `$_GET`/`$_POST`/`$_REQUEST`/`$_SERVER`, bypass enkode `base64_decode()` | Critical |
| **data_leak** | PAN kartu kredit 16 digit (Visa/MasterCard/AmEx/Discover/JCB/Diners), AWS Access Key `AKIA...`, header kunci privat PEM `-----BEGIN`, API Key OpenAI/LLM `sk-...`, string koneksi database `mongodb://`/`mysql://`/`postgresql://`/`redis://` (**wajib memuat userinfo `@`**: `mysql://root:secret@db` dilaporkan, sedangkan `redis://shared-memory` dan `postgres://localhost:5432/app` adalah konfigurasi biasa dan **tidak dilaporkan**), `jdbc:` (tanpa batasan itu), JWT Token | Critical |

---

## Batas yang Diketahui

Berikut adalah batas yang **diketahui dan sengaja dipertahankan**, bukan cacat yang menunggu perbaikan. Setiap butir punya bukti pengukuran, dan setiap butir sudah pernah menggagalkan upaya memperketatnya.

### `dns_rebinding` melaporkan, tidak memblokir

Kriterianya adalah «alamat internal muncul di `Host:`» — dan bentuk yang sama juga merupakan setiap panggilan antar-pod k8s (`Host: 10.244.1.5:8080`), setiap pengembangan lokal (`Host: localhost:8000`), dan setiap permintaan jaringan kontainer Docker (`172.18.0.2`). Rebinding yang sebenarnya melihat «nama domain publik + hasil resolusi yang mengarah ke dalam», sedangkan `Host` yang dikirim peramban justru nama publik itu — **satu string tidak membawa riwayat resolusi**, sehingga bentuk yang diuji detektor ini tidak beririsan dengan bentuk serangan, dan tidak ada arah pengetatan. Karena itu seluruh detektor hanya berisi tingkat lemah dan selalu melaporkan `Low`; sebanyak apa pun tumpukannya tidak akan melewati garis tolak sendirian. Perlindungan berada **setelah** resolusi, membandingkan IP hasilnya, bukan di lapisan string.

### Pustaka ini tidak bisa memindai sumber, tes, dan dokumentasinya sendiri

Langit-langit pemindai tanda tangan: terukur pada repositori ini, 78 dari 298 berkas melewati garis tolak, dan semuanya memuat string serangan **secara konstruksi** — payload tes, literal regex dari sumber detektor itu sendiri, serta tabel README dan OWASP yang mencantumkan pola-pola tersebut. README tidak menjadi cacat karena menuliskan `(a+)+`. Untuk memindai artefak sendiri, kecualikan dulu korpus itu, atau ganti kriteria.

### `upload` selalu melaporkan `<%@` / `<?php` sebagai Critical

Kontrak detektor ini adalah «**blob ini adalah kode yang dapat dieksekusi di sisi server**» — kemunculannya sudah cukup, jadi tidak ada pemisahan tingkat. Halaman JSP dan webshell JSP berbagi byte pembuka yang identik (`<%@ page language="java" … %>` dan `<%@ page import="java.io.*" %>` adalah bentuk yang sama); menurunkan `<%@`/`<%=` berarti menjatuhkan webshell ke bawah garis tolak — itu menghapus deteksi dengan cara lain. Harganya, memindai halaman yang **sedang disajikan** (bukan berkas yang diunggah) juga terkena; itu ketidaksesuaian ranah input — pesan temuan `Malicious file upload detected` sudah menyebut ranahnya.

### `path_traversal` melaporkan `(?:\.\./){2,}` sebagai Critical

Path relatif yang dalam di monorepo (`from '../../../shared/domain'`) akan terkena. Tidak diperketat lebih lanjut karena satu-satunya batasan yang memisahkannya dari serangan adalah daftar nama berkas target (`../etc/passwd` dan sejenisnya), yang hanya mencakup berkas sistem — penyerang tinggal mengganti target LFI.

---

## Siklus Hidup

<img src="../../diagrams/lifecycle.svg" alt="security-rust — tiga siklus hidup: pemindaian, sesi, pembatasan laju" width="900">

Tiga siklus hidup berjalan independen, dan satu-satunya titik temu adalah fungsi penanganan permintaan milik pemanggil:
*(Anotasi diagram dalam bahasa Mandarin; labelnya adalah nama API.)*

| Siklus hidup | Dimulai di | Berakhir di | Tempat state berada |
|-----------|-----------|---------|----------------|
| **Pemindaian** | `Scanner::scan(&str)` | `Vec<DetectionResult>` → `score::assess` → `RiskAssessment` | Tidak ada — stateless, independen per pemanggilan |
| **Sesi** | `SessionGuard::bind()` menulis `SessionRecord` | `verify()` per permintaan → `SessionVerdict` ⇒ `Allow` / `Challenge` / `Block` | `SessionStore` (bawaan `MemoryStore`) |
| **Pembatasan laju** | `Throttle::check_any(&[keys])` | `Allow{remaining}` / `Banned{until}` / `Unavailable` | `ThrottleStore` (bawaan `MemoryThrottleStore`) |

Dua batas yang mudah keliru:

- **`remaining == 0` berarti permintaan ini harus ditolak** — kuota sudah habis, bukan «masih bisa coba sekali lagi». Jangan terbalik saat menulis header `X-RateLimit-*`.
- **Kegagalan penyimpanan ditangani ke arah yang berlawanan**: `SessionGuard` bersifat fail-closed (`StoreUnavailable` ⇒ `Block`, tidak pernah meloloskan — jika tidak, penyerang yang memicu kegagalan backend menukar seluruh kelas pemeriksaan); `Throttle` bersifat fail-open (`Unavailable` diserahkan ke pemanggil, karena memblokir semua pengguna saat backend tergelincir adalah DoS terhadap diri sendiri, dan gerbang utama `SessionGuard` tetap memblokir). Ini keputusan desain yang tertulis, bukan penanganan yang hilang.

---

## Cara Penggunaan

Siap pakai tanpa konfigurasi:

```rust
use security_rust::Scanner;

let scanner = Scanner::default();

// Sinyal kuat: bentuknya sendiri hanya mungkin berasal dari serangan ⇒ severity yang dideklarasikan detektor
let results = scanner.scan("<img src=x onerror=alert(1)>");
// [CRITICAL] XSS cross-site scripting detected — offset: 11, pattern: onerror=

// Sinyal lemah: token hanya muncul ⇒ selalu Low, tidak melewati garis tolak sendirian (lihat «Dua Tingkat»)
let weak = scanner.scan("<script src=\"/app.js\"></script>");
// [LOW] XSS tag present (weak signal) — offset: 0, pattern: <script>
```

Penilaian risiko merangkum daftar temuan menjadi satu tingkat, agar beberapa sinyal berisiko rendah tidak diabaikan diam-diam:

```rust
let assessment = scanner.assess("=cmd|' /C calc'!A0 `cat /etc/passwd` ../../../etc/passwd");
// assessment.level   >= RiskLevel::High
// assessment.results >= 3
// assessment.score   — poin berbobot mentah
```

Referensi API lengkap (instalasi, pemindaian selektif, konfigurasi kustom, penilaian risiko, tampilan severity, keamanan sesi, pembatasan laju dan pemblokiran, performa) lihat [Referensi API](./API.md).

### Keamanan Sesi (`session`)

```rust
use security_rust::session::{Decision, MemoryStore, RequestContext, SessionConfig, SessionGuard};

let guard = SessionGuard::new(MemoryStore::new(), SessionConfig::default());

let login = RequestContext {
    token: "tok-abc",
    subject: "u-1",
    fingerprint: "ip=1.2.3.4|ua=curl",   // fingerprint klien, diikat saat login
    location: Some("CN-BJ"),
    coords: Some((39.9042, 116.4074)),
    signature: None,                      // MAC ditandatangani oleh pemanggil
    at: None,
};

// Login: buat sesi + ikat fingerprint + catat lokasi;
// lokasi berbeda hanya memengaruhi keputusan, tidak memblokir login
guard.bind(&login, 1_700_000_000).unwrap();

// Verifikasi tiap permintaan: token sama dengan fingerprint berbeda ⇒ pembajakan klien
let verdict = guard.verify(&RequestContext { fingerprint: "ip=5.6.7.8|ua=curl", ..login }, 1_700_000_010);

match verdict.decision {
    Decision::Allow => { /* izinkan */ }
    Decision::Challenge => { /* izinkan tetapi minta verifikasi kedua: lokasi berbeda, jam menyimpang, signature tak terduga */ }
    Decision::Block => { /* tolak */ }
}
```

### Pembatasan Laju dan Pemblokiran (`throttle`)

```rust
use security_rust::throttle::{MemoryThrottleStore, Throttle, ThrottleConfig, ThrottleDecision};

let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());
let key = "acct:u-1"; // key dibuat dan dinormalkan oleh pemanggil, jangan pakai input mentah sebagai key
let now = 1_700_000_000;

// Permintaan nyata punya dua dimensi: IP dan akun. check_any menanyakan keduanya sekaligus, lalu menggabungkan yang terketat
match throttle.check_any(&["ip:1.2.3.4", key], now) {
    // remaining bisa ditulis ke X-RateLimit-*; **remaining == 0 berarti permintaan ini harus ditolak**
    ThrottleDecision::Allow { remaining } => { /* sisa kuota: remaining */ }
    // now >= until sudah dianggap bebas blokir
    ThrottleDecision::Banned { until } => { /* diblokir sampai until */ }
    // kegagalan backend: modul ini tidak memutuskan untuk pemanggil (disarankan: izinkan + beri peringatan)
    ThrottleDecision::Unavailable => { /* backend pembatasan laju tidak tersedia */ }
}

// Catat satu kegagalan autentikasi: mencapai threshold berarti diblokir. Mengembalikan ThrottleOutcome (dua keadaan),
// sedangkan kegagalan penyimpanan menjadi Err — tidak perlu menulis kode untuk arm Unavailable yang tak pernah dieksekusi
let _ = throttle.record_failure(key, now);
```

---

## Pengembangan

```bash
# Build
cargo build --release

# Tes (580: 431 unit + 148 integrasi + 1 doc test)
cargo test

# Contoh pipeline end-to-end (pemindaian → pembatasan laju → sesi → tindakan)
cargo run --example waf

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
