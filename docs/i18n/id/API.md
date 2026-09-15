<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# Referensi API security-rust

[中文](../../README.md) | [English](../en/API.md) | [한국어](../ko/API.md) | [Русский](../ru/API.md) | [Deutsch](../de/API.md) | [Français](../fr/API.md) | [Español](../es/API.md) | [Português](../pt/API.md) | [हिन्दी](../hi/API.md) | [العربية](../ar/API.md) | [বাংলা](../bn/API.md) | [日本語](../ja/API.md) | [Bahasa Indonesia (本页)](./API.md)

---

## Trait Inti

### `Detector`

Satu-satunya kontrak untuk semua detektor:

```rust
pub trait Detector {
    fn name(&self) -> &str;
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

## Scanner

### Instalasi

```toml
[dependencies]
security-rust = "1.0.8"
```

### Mulai Cepat

```rust
use security_rust::Scanner;

fn main() {
    // tanpa konfigurasi: rakit seluruh 32 detektor
    let scanner = Scanner::default();

    // pindai input, kembalikan semua serangan yang terdeteksi
    let results = scanner.scan("<script>alert('xss')</script>");

    for r in &results {
        println!("[{}] {} — offset: {}, pattern: {}",
            r.severity, r.message, r.offset, r.matched_pattern);
    }
    // Output:
    // [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
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

## Modul Stateful dan Penilaian Risiko

Ketiga modul ini tersedia langsung dari akar crate. `session` dan `throttle` sengaja tidak mengimplementasikan trait `Detector` karena inputnya majemuk. Tidak ada dependensi eksternal baru: token dan signature (MAC) disediakan pemanggil, dan parsing lokasi juga tanggung jawab pemanggil.

### `session` — keamanan sesi

```rust
use security_rust::session::{MemoryStore, RequestContext, SessionConfig, SessionGuard};

let guard = SessionGuard::new(MemoryStore::new(), SessionConfig::default());

let v = guard.bind(&ctx, now)?;        // Result<SessionVerdict, SessionError>
let v = guard.verify(&ctx, now);       // SessionVerdict
guard.revoke(token)?;                  // Result<(), StoreError>
let n = guard.revoke_all(subject)?;    // Result<usize, StoreError>
guard.rotate(old, new, &ctx, now)?;    // Result<(), SessionError>
```

- Bidang `RequestContext`: `token`, `subject`, `fingerprint`, `location`, `coords`, `signature`, `at`
- Bidang `SessionVerdict`: `decision`, `severity`, `threats`
- `Decision`: `Allow` | `Challenge` | `Block`
- Saat penyimpanan tidak tersedia hasilnya `Decision::Block` (sebab `StoreUnavailable`) — jadi **fail-closed**, tidak ada jalur yang meloloskan
- Default `SessionConfig`: `ttl_secs` = 3600, `impossible_travel_kmh` = 900.0, `timestamp_skew_secs` = 300
- Penyimpanan diabstraksi melalui trait `SessionStore`, implementasi siap pakai `MemoryStore`; untuk deployment multi-instans implementasikan trait ini untuk Redis

### `throttle` — pembatasan laju

```rust
use security_rust::throttle::{MemoryThrottleStore, Throttle, ThrottleConfig, ThrottleDecision};

let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());

match throttle.check(key, now) {
    ThrottleDecision::Allow { remaining } => { /* diizinkan */ }
    ThrottleDecision::Banned { until } => { /* diblokir */ }
    ThrottleDecision::Unavailable => { /* penyimpanan tidak tersedia */ }
}
throttle.record_failure(key, now)?;  // Result<ThrottleDecision, StoreError>
throttle.record_success(key)?;       // Result<(), StoreError>
throttle.reset(key)?;                // Result<(), StoreError>
throttle.purge_expired(now)?;        // Result<usize, StoreError>
```

- Default `ThrottleConfig`: `threshold` = 5, `window_secs` = 60, `ban_secs` = 900
- **Pengecualian yang disengaja**: saat penyimpanan gagal ia mengembalikan `Unavailable`, bukan `Banned` — pembatasan laju adalah defense-in-depth, bukan gerbang autentikasi utama; memblokir semua pengguna karena gangguan backend adalah DoS terhadap diri sendiri, dan keputusannya diserahkan ke pemanggil
- Penyimpanan diabstraksi melalui trait `ThrottleStore`, implementasi siap pakai `MemoryThrottleStore`

### `score` — penilaian risiko

```rust
use security_rust::assess;

let results = Scanner::default().scan(input);
let a = assess(&results);
println!("{} {}", a.level, a.score);   // misalnya: HIGH 40

let a = Scanner::default().assess(input);  // langsung RiskAssessment
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

## Performa

Pada build Release, pola regex dikompilasi statis lewat `LazyLock` dan tidak dikompilasi ulang setelah pemakaian pertama; biaya pemindaian satu regex berada di kisaran ratusan nanodetik. Pemindaian penuh 32 detektor atas input 26 byte memakan sekitar ~50μs/kali (pengukuran lokal, tumbuh seiring jumlah regex dan panjang input). Cocok untuk skenario throughput tinggi (gateway API, pipeline log).
