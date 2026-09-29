<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# Referensi API security-rust

[中文](../../../README.md) | [English](../en/API.md) | [한국어](../ko/API.md) | [Русский](../ru/API.md) | [Deutsch](../de/API.md) | [Français](../fr/API.md) | [Español](../es/API.md) | [Português](../pt/API.md) | [हिन्दी](../hi/API.md) | [العربية](../ar/API.md) | [বাংলা](../bn/API.md) | [日本語](../ja/API.md) | [Bahasa Indonesia (本页)](./API.md)

---

## Trait Inti

### `Detector`

Satu-satunya kontrak untuk semua detektor:

```rust
pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
    fn detect(&self, input: &str) -> Option<DetectionResult>;
}
```

- `name()` — nama detektor (mis. `"xss"`, `"sql_injection"`)
- `detect()` — memindai input; jika terdeteksi, mengembalikan `Some(DetectionResult)`, jika tidak, mengembalikan `None`

> `session` dan `throttle` sengaja tidak mengimplementasikan trait ini — inputnya majemuk (token + fingerprint + lokasi + waktu) yang tidak dapat diungkapkan oleh `Detector::detect(&str)`. Lihat «Modul Stateful dan Penilaian Risiko» di bawah.

## Struktur Hasil Deteksi

```rust
pub struct DetectionResult {
    pub attack_type: String,      // "xss", "sql_injection" ...
    pub category: AttackCategory, // Injection | Protocol | Data | File
    pub severity: Severity,       // Critical | High | Medium | Low
    pub matched_pattern: String,  // potongan pola yang cocok
    pub offset: usize,            // offset byte pada input
    pub message: String,          // keterangan yang mudah dibaca
}
```

## Dua Tingkat: Sinyal Kuat dan Sinyal Lemah

18 dari 32 detektor membagi polanya menjadi dua tingkat (static `STRONG_PATTERNS` / `WEAK_PATTERNS` di dalam sumber). Struktur bidang `DetectionResult` tidak berubah; yang berubah adalah nilai `severity`:

| Tingkat | Kriteria | `severity` | Satu temuan bisa melewati garis tolak? |
|------|------|-----------|------------------|
| **Kuat** | Bentuknya sendiri hanya mungkin berasal dari serangan | Tingkat yang dideklarasikan detektor | Bisa |
| **Lemah** | Token itu hanya *muncul* — ada di mana-mana dalam konten normal | Selalu `Severity::Low` (5 poin) | **Tidak** |

Detektor yang sama, `attack_type` yang sama, hanya `severity` yang berbeda. `detect()` mencoba tingkat kuat lebih dulu dan beralih ke tingkat lemah bila tidak ada yang cocok, sehingga **setiap detektor mengembalikan paling banyak satu hasil**. Sinyal lemah tetap terdeteksi dan tidak dibuang diam-diam.

`DetectionResult` sendiri tidak membedakan tingkat —— untuk mengetahui sebuah temuan kuat atau lemah, lihat `severity == Severity::Low` (tingkat lemah adalah satu-satunya sumber yang melaporkan `Low`). Garis tolak pipeline rujukan adalah 40 poin (`risk.level >= RiskLevel::High`, [`examples/waf.rs:166`](../../../examples/waf.rs)); satu sinyal lemah hanya 5 poin sehingga tidak masuk ke cabang itu.

Untuk melihat serangan di balik sinyal lemah, `assess()` menumpuk temuan dari beberapa detektor:

```rust
let scanner = Scanner::default();

// Tiga sinyal lemah di tiga detektor berbeda. Hanya tumpukannya yang mencapai Medium (15 poin), masih di bawah High
let a = scanner.assess("<script src=\"/app.js\"></script>\n../config\n__proto__");
assert_eq!(a.results, 3);
assert_eq!(a.score, 15);
assert_eq!(a.level, RiskLevel::Medium);
```

Contoh bentuk yang diturunkan menjadi sinyal lemah (daftar lengkapnya ada di `WEAK_PATTERNS` tiap detektor): `<script src=...>`, `../` satu tingkat, `-2` di awal baris, `__proto__` telanjang, `${env:}`, `X-Forwarded-Host`, `Host: localhost`, `10.0.0.5` telanjang, `//evil.com`, `information_schema`.

Kriterianya adalah **bentuk**, bukan nama berkas: untuk `../` yang sama, satu tingkat (`../x`) melaporkan `Low` dan banyak tingkat (`../../`) melaporkan `Critical` ([`src/file/path_traversal.rs`](../../../src/file/path_traversal.rs)). Sejauh mana tiap detektor dapat mencapai tingkat tertentu ada di tabel-tabel berikut dan tabel fitur di [README](./README.md).

## Scanner

### Instalasi

```toml
[dependencies]
security-rust = "3.0.0"
```

### Mulai Cepat

```rust
use security_rust::Scanner;

fn main() {
    // tanpa konfigurasi: rakit seluruh 32 detektor
    let scanner = Scanner::default();

    // pindai input, kembalikan semua serangan yang terdeteksi (tiap detektor paling banyak satu)
    let results = scanner.scan("<img src=x onerror=alert(1)>");

    for r in &results {
        println!("[{}] {} — offset: {}, pattern: {}",
            r.severity, r.message, r.offset, r.matched_pattern);
    }
    // Output:
    // [CRITICAL] XSS cross-site scripting detected — offset: 11, pattern: onerror=

    // Sinyal lemah melewati detektor dan attack_type yang sama, hanya severity-nya Low
    let weak = scanner.scan("<script src=\"/app.js\"></script>");
    // [LOW] XSS tag present (weak signal) — offset: 0, pattern: <script>
}
```

### Pemindaian Selektif

```rust
let scanner = Scanner::default();

// jalankan hanya detektor yang ditentukan
let results = scanner.scan_with(
    "1 UNION SELECT password FROM users",
    &["sql_injection", "xss"],
);
```

### Konfigurasi Kustom

```rust
use security_rust::injection::{XssDetector, SqlInjectionDetector};

// rakit hanya detektor yang diperlukan melalui builder
let scanner = Scanner::builder()
    .with_detector(Box::new(XssDetector))
    .with_detector(Box::new(SqlInjectionDetector))
    .build();
```

### Menampilkan Severity

```rust
use security_rust::Severity;

let r = &results[0];
println!("{}", r.severity);  // CRITICAL | HIGH | MEDIUM | LOW
```

Label status lainnya juga mengimplementasikan `Display` dan dicetak huruf besar: `Decision` (`ALLOW` / `CHALLENGE` / `BLOCK`), `SessionThreat` (mis. `impossible travel (11205 km/h)`), `AttackCategory` (huruf kecil, mis. `injection`), `ThrottleDecision` (`ALLOW` / `BANNED` / `UNAVAILABLE`), dan `ThrottleOutcome` (`ALLOW` / `BANNED`).

```rust
println!("{} {}", verdict.decision, verdict.threats.len());  // BLOCK 2
```

## Modul Stateful dan Penilaian Risiko

Ketiga modul ini tersedia langsung dari akar crate. `session` dan `throttle` sengaja tidak mengimplementasikan trait `Detector` karena inputnya majemuk. Tidak ada dependensi eksternal baru: token dan signature (MAC) disediakan pemanggil, dan parsing lokasi juga tanggung jawab pemanggil.

### `session` — keamanan sesi

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

- `purge_expired` menghapus sesi yang sudah kedaluwarsa beserta riwayat login subjek yang dorman. **Nilai kembaliannya hanya menghitung sesi**, tidak termasuk riwayat login yang didaur ulang
- Bidang `RequestContext`: `token`, `subject`, `fingerprint`, `location`, `coords`, `signature`, `at`
- Bidang `SessionVerdict`: `decision`, `severity: Option<Severity>` (`None` saat diizinkan), `threats`
- `subject` **hanya dipakai `bind`; `verify` mengabaikannya sepenuhnya**: identitas tiap permintaan selalu diambil dari `SessionRecord` di server (riwayat lokasi asing diagregasi pada `record.subject`), dan `subject` yang dikirim pemanggil tidak tepercaya; karena itu `subject: ""` dari middleware sah (`bind` yang menuntut nilai tidak kosong). Justru karena itu **jangan pernah** menaruh identitas pengguna dari header permintaan di sini — hari ini ia tidak sampai ke keputusan, tetapi refactor di masa depan tidak wajib mempertahankannya.
- `Decision`: `Allow` | `Challenge` | `Block`
- Saat penyimpanan tidak tersedia hasilnya `Decision::Block` (sebab `StoreUnavailable`) — jadi **fail-closed**, tidak ada jalur yang meloloskan
- Default `SessionConfig`: `ttl_secs` = 3600, `impossible_travel_kmh` = 900.0, `timestamp_skew_secs` = 300
- Penyimpanan diabstraksi melalui trait `SessionStore`, implementasi siap pakai `MemoryStore`; untuk deployment multi-instans implementasikan trait ini untuk Redis

### `throttle` — pembatasan laju

```rust
use security_rust::throttle::{MemoryThrottleStore, Throttle, ThrottleConfig, ThrottleDecision, ThrottleOutcome};

let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());

let key = "acct:user-42";
let now = 1_700_000_000u64;

match throttle.check(key, now) {
    ThrottleDecision::Allow { remaining } => { /* diizinkan */ }
    ThrottleDecision::Banned { until } => { /* diblokir */ }
    ThrottleDecision::Unavailable => { /* penyimpanan tidak tersedia */ }
}
// Periksa beberapa dimensi sekaligus (mis. IP + akun): hasil terketat yang dipakai
let merged = throttle.check_any(&["ip:203.0.113.7", "acct:user-42"], now);  // ThrottleDecision
let outcome = throttle.record_failure(key, now)?;  // Result<ThrottleOutcome, StoreError>
throttle.record_success(key)?;       // Result<(), StoreError>
throttle.reset(key)?;                // Result<(), StoreError>
throttle.purge_expired(now)?;        // Result<usize, StoreError>
```

- Default `ThrottleConfig`: `threshold` = 5, `window_secs` = 60, `ban_secs` = 900
- `check_any(&[key, ...], now)` menggabungkan beberapa dimensi: `Banned` menang (dengan `until` terjauh), jika tidak `Unavailable`, jika tidak `Allow` dengan `remaining` terkecil; daftar kosong menghasilkan `Allow { remaining: 0 }`
- `ThrottleOutcome` (`Allow { remaining }` | `Banned { until }`) adalah hasil `record_failure`; tidak memuat `Unavailable` karena kegagalan penyimpanan kembali sebagai `Err(StoreError)`
- **Pengecualian yang disengaja**: saat penyimpanan gagal `check` / `check_any` mengembalikan `Unavailable`, bukan `Banned` — pembatasan laju adalah defense-in-depth, bukan gerbang autentikasi utama; memblokir semua pengguna karena gangguan backend adalah DoS terhadap diri sendiri, dan keputusannya diserahkan ke pemanggil
- Penyimpanan diabstraksi melalui trait `ThrottleStore`, implementasi siap pakai `MemoryThrottleStore`

### `score` — penilaian risiko

```rust
use security_rust::{assess, Scanner};

let results = Scanner::default().scan("=cmd|' /C calc'!A0 `cat /etc/passwd` ../../../etc/passwd");
let a = assess(&results);
println!("{} {}", a.level, a.score);   // misalnya: CRITICAL 150

let a = Scanner::default().assess("=cmd|' /C calc'!A0 `cat /etc/passwd` ../../../etc/passwd");  // langsung RiskAssessment
```

- `RiskLevel`: `None` | `Low` | `Medium` | `High` | `Critical`
- Bidang `RiskAssessment`: `level`, `score`, `results` (jumlah hasil yang ikut digabung)
- Bobot: Critical = 100, High = 40, Medium = 15, Low = 5

## Jalur Modul

| Modul | Jalur | Jumlah Detektor |
|------|------|---------|
| Inti | `src/lib.rs` `result.rs` `scanner.rs` | — |
| Injeksi | `src/injection/` | 11 |
| Protokol | `src/protocol/` | 11 |
| Data | `src/data/` | 7 |
| File | `src/file/` | 3 |
| Sesi | `src/session/` | — |
| Pembatasan laju | `src/throttle/` | — |
| Penilaian risiko | `src/score.rs` | — |
| Maskot | `src/pet.rs` | — |

## Batas yang Diketahui

Berikut adalah batas yang **diketahui dan sengaja dipertahankan**, bukan cacat yang menunggu perbaikan. Setiap butir punya bukti pengukuran, dan setiap butir sudah pernah menggagalkan upaya memperketatnya.

### `dns_rebinding` melaporkan, tidak memblokir

Kriterianya adalah «alamat internal muncul di `Host:`» — dan bentuk yang sama juga merupakan setiap panggilan antar-pod k8s (`Host: 10.244.1.5:8080`), setiap pengembangan lokal (`Host: localhost:8000`), dan setiap permintaan jaringan kontainer Docker (`172.18.0.2`). Rebinding yang sebenarnya melihat «nama domain publik + hasil resolusi yang mengarah ke dalam», sedangkan `Host` yang dikirim peramban justru nama publik itu — **satu string tidak membawa riwayat resolusi**, sehingga bentuk yang diuji detektor ini tidak beririsan dengan bentuk serangan, dan tidak ada arah pengetatan. Karena itu seluruh detektor hanya berisi tingkat lemah dan selalu melaporkan `Low`; sebanyak apa pun tumpukannya tidak akan melewati garis tolak sendirian. Perlindungan berada **setelah** resolusi, membandingkan IP hasilnya, bukan di lapisan string.

### Pustaka ini tidak bisa memindai sumber, tes, dan dokumentasinya sendiri

Langit-langit pemindai tanda tangan: terukur pada repositori ini, 78 dari 298 berkas melewati garis tolak, dan semuanya memuat string serangan **secara konstruksi** — payload tes, literal regex dari sumber detektor itu sendiri, serta tabel README dan OWASP yang mencantumkan pola-pola tersebut. README tidak menjadi cacat karena menuliskan `(a+)+`. Untuk memindai artefak sendiri, kecualikan dulu korpus itu, atau ganti kriteria.

### `upload` selalu melaporkan `<%@` / `<?php` sebagai Critical

Kontrak detektor ini adalah «**blob ini adalah kode yang dapat dieksekusi di sisi server**» — kemunculannya sudah cukup, jadi tidak ada pemisahan tingkat. Halaman JSP dan webshell JSP berbagi byte pembuka yang identik (`<%@ page language="java" … %>` dan `<%@ page import="java.io.*" %>` adalah bentuk yang sama); menurunkan `<%@`/`<%=` berarti menjatuhkan webshell ke bawah garis tolak — itu menghapus deteksi dengan cara lain. Harganya, memindai halaman yang **sedang disajikan** (bukan berkas yang diunggah) juga terkena; itu ketidaksesuaian ranah input.

### `path_traversal` melaporkan `(?:\.\./){2,}` sebagai Critical

Path relatif yang dalam di monorepo (`from '../../../shared/domain'`) akan terkena. Tidak diperketat lebih lanjut karena satu-satunya batasan yang memisahkannya dari serangan adalah daftar nama berkas target (`../etc/passwd` dan sejenisnya), yang hanya mencakup berkas sistem — penyerang tinggal mengganti target LFI.

## Performa

Pada build Release, setiap detektor menyimpan polanya dalam tabel statis `static PATTERNS: LazyLock<Vec<Regex>>`, sehingga setiap regex dikompilasi sekali saat pertama dipakai di dalam proses dan dipakai ulang pada setiap panggilan berikutnya tanpa biaya kompilasi lagi. Pemindaian penuh 32 detektor memakan waktu puluhan mikrodetik per kali, dan biaya ini tumbuh seiring jumlah detektor dan panjang input; ukur nilai sebenarnya di perangkat dan beban kerja Anda sendiri. Cocok untuk skenario throughput tinggi (gateway API, pipeline log).
