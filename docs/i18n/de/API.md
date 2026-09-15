<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust API-Referenz

[中文](../../README.md) | [English](../en/API.md) | [한국어](../ko/API.md) | [Русский](../ru/API.md) | [Français](../fr/API.md) | [Español](../es/API.md) | [Português](../pt/API.md) | [हिन्दी](../hi/API.md) | [العربية](../ar/API.md) | [বাংলা](../bn/API.md) | [Bahasa Indonesia](../id/API.md) | [日本語](../ja/API.md) | [Deutsch (本页)](./API.md)

---

## Kern-Trait

### `Detector`

Der einzige Vertrag aller Detektoren:

```rust
pub trait Detector {
    fn name(&self) -> &str;
    fn detect(&self, input: &str) -> Option<DetectionResult>;
}
```

- `name()` — Name des Detektors (z. B. `"xss"`, `"sql_injection"`)
- `detect()` — scannt die Eingabe; bei Treffer wird `Some(DetectionResult)` zurückgegeben, sonst `None`

## Struktur des Erkennungsergebnisses

```rust
pub struct DetectionResult {
    pub attack_type: String,      // "xss", "sql_injection" ...
    pub category: AttackCategory, // Injection | Protocol | Data | File
    pub severity: Severity,       // Critical | High | Medium | Low
    pub matched_pattern: String,  // der konkret getroffene Musterausschnitt
    pub offset: usize,            // Byte-Offset in der Eingabe
    pub message: String,          // menschenlesbare Beschreibung
}
```

## Scanner

### Installation

```toml
[dependencies]
security-rust = "1.1.0"
```

### Schnellstart

```rust
use security_rust::Scanner;

fn main() {
    // Null Konfiguration: montiert alle 32 Detektoren
    let scanner = Scanner::default();

    // Scannt die Eingabe und liefert alle erkannten Angriffe
    let results = scanner.scan("<script>alert('xss')</script>");

    for r in &results {
        println!("[{}] {} — offset: {}, pattern: {}",
            r.severity, r.message, r.offset, r.matched_pattern);
    }
    // Ausgabe:
    // [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
}
```

### Selektives Scannen

```rust
let scanner = Scanner::default();

// Nur die angegebenen Detektoren ausführen
let results = scanner.scan_with(
    "1 UNION SELECT password FROM users",
    &["sql_injection", "xss"],
);
```

### Benutzerdefinierte Konfiguration

```rust
use security_rust::injection::{XssDetector, SqlInjectionDetector};

// Über den Builder nur die benötigten Detektoren montieren
let scanner = Scanner::builder()
    .with_detector(Box::new(XssDetector))
    .with_detector(Box::new(SqlInjectionDetector))
    .build();
```

### Schweregrad-Anzeige

```rust
use security_rust::Severity;

let r = &results[0];
println!("{}", r.severity);  // CRITICAL | HIGH | MEDIUM | LOW
```

Auch die übrigen Zustandslabels sind als `Display` implementiert und werden in Großbuchstaben ausgegeben: `Decision` (`ALLOW` / `CHALLENGE` / `BLOCK`), `SessionThreat` (z. B. `impossible travel (11205 km/h)`), `AttackCategory` (kleingeschrieben, z. B. `injection`), `ThrottleDecision` (`ALLOW` / `BANNED` / `UNAVAILABLE`) und `ThrottleOutcome` (`ALLOW` / `BANNED`).

```rust
println!("{} {}", verdict.decision, verdict.threats.len());  // BLOCK 2
```

## Zustandsbehaftete Module

`session` und `throttle` implementieren **absichtlich nicht** das `Detector`-Trait: Sie sind zustandsbehaftet und identitätsbezogen, und `Detector::detect(&self, input: &str)` kann eine zusammengesetzte Eingabe aus Token, Fingerabdruck, Position und Zeit nicht ausdrücken. `score` ist ein reiner Rechenbaustein über `DetectionResult`.

```rust
use security_rust::{
    Decision, MemoryStore, MemoryThrottleStore, Scanner,
    SessionConfig, SessionGuard, SessionVerdict,
    Throttle, ThrottleConfig, ThrottleDecision, ThrottleOutcome,
};

// Sitzungsschutz — fail-closed: bei Speicherfehler Decision::Block
let sessions = SessionGuard::new(MemoryStore::new(), SessionConfig::default());
let verdict: SessionVerdict = sessions.verify(&ctx, now);
if verdict.decision == Decision::Block {
    // ablehnen
}

// Ratenbegrenzung — Defense-in-Depth: bei Backend-Ausfall Unavailable, nicht Banned
let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());
match throttle.check("user:42", now) {
    ThrottleDecision::Allow { remaining: 0 } => { /* ablehnen: Kontingent erschöpft */ }
    ThrottleDecision::Allow { .. } => { /* durchlassen */ }
    ThrottleDecision::Banned { until } => { /* gesperrt bis `until` */ }
    ThrottleDecision::Unavailable => { /* selbst entscheiden */ }


// Mehrere Dimensionen zusammenführen (z. B. IP + Konto): das strengste Ergebnis gewinnt
let merged = throttle.check_any(&["ip:203.0.113.7", "user:42"], now);
match throttle.record_failure("user:42", now) {
    Ok(outcome) => { /* ThrottleOutcome: Allow { remaining } | Banned { until } */ }
    Err(_) => { /* Speicherfehler */ }
}
}

// Risikobewertung: Einzelsignale zu einer messbaren Größe aggregieren
let risk = Scanner::default().assess(input);
```

| Element | Signatur / Feld |
|------|------|
| `SessionGuard::bind` | `fn bind(&self, ctx: &RequestContext, now: u64) -> Result<SessionVerdict, SessionError>` |
| `SessionGuard::verify` | `fn verify(&self, ctx: &RequestContext, now: u64) -> SessionVerdict` |
| `SessionGuard::revoke` / `revoke_all` | `fn revoke(&self, token: &str) -> Result<(), StoreError>` / `fn revoke_all(&self, subject: &str) -> Result<usize, StoreError>` |
| `SessionGuard::rotate` | erneuert das Token einer Sitzung |
| `RequestContext` | `token`, `subject`, `fingerprint`, `location`, `coords`, `signature`, `at` |
| `SessionVerdict` | `decision: Decision`, `severity: Option<Severity>` (bei Freigabe `None`), `threats: Vec<SessionThreat>` |
| `Decision` | `Allow` \| `Challenge` \| `Block` |
| `SessionConfig` | `ttl_secs` 3600, `impossible_travel_kmh` 900.0, `timestamp_skew_secs` 300 |
| `SessionStore` | Trait für den Sitzungsspeicher; `MemoryStore` ist die mitgelieferte In-Memory-Implementierung |
| `Throttle::check` | `fn check(&self, key: &str, now: u64) -> ThrottleDecision` |
| `Throttle::check_any` | `fn check_any(&self, keys: &[&str], now: u64) -> ThrottleDecision` — führt mehrere Dimensionen zusammen: `Banned` schlägt alles (spätestes `until`), sonst `Unavailable`, sonst `Allow` mit dem kleinsten `remaining` |
| `Throttle::record_failure` | `fn record_failure(&self, key: &str, now: u64) -> Result<ThrottleOutcome, StoreError>` |
| `Throttle::record_success` / `reset` / `purge_expired` | `fn record_success(&self, key: &str) -> Result<(), StoreError>` / `fn reset(&self, key: &str) -> Result<(), StoreError>` / `fn purge_expired(&self, now: u64) -> Result<usize, StoreError>` |
| `ThrottleConfig` | `threshold` 5, `window_secs` 60, `ban_secs` 900 |
| `ThrottleDecision` | `Allow { remaining }` \| `Banned { until }` \| `Unavailable` — nur aus `check` / `check_any` |
| `ThrottleOutcome` | `Allow { remaining }` \| `Banned { until }` — Ergebnis von `record_failure`; ohne `Unavailable`, weil ein Speicherfehler dort als `Err(StoreError)` zurückkommt |
| `ThrottleStore` | Trait für den Zähler-Speicher; `MemoryThrottleStore` ist die mitgelieferte In-Memory-Implementierung |
| `RiskLevel` | `None` \| `Low` \| `Medium` \| `High` \| `Critical` |
| `RiskAssessment` | Ergebnis von `Scanner::assess` |
| `Scanner::assess` | `fn assess(&self, input: &str) -> RiskAssessment` |

Zu beachten: `ThrottleDecision::Allow { remaining: 0 }` bedeutet, dass **diese** Anfrage abzulehnen ist — das Kontingent ist verbraucht, nicht „noch ein Versuch übrig". Der Zweig heißt `Allow` und nicht `Banned`, weil zu diesem Zeitpunkt keine Sperre aktiv ist. `Unavailable` entsteht nur in `check` / `check_any`; `record_failure` gibt `ThrottleOutcome` zurück, das diesen Zweig bewusst nicht kennt — ein Speicherfehler wird dort zu `Err(StoreError)`.

Ein `RequestContext` wird vollständig vom Aufrufer befüllt: Die Bibliothek fordert keine Geo-Datenbank an und validiert keine Signaturen, sondern vergleicht nur die übergebenen Werte mit der bei `bind` hinterlegten Basis.

`subject` wird **nur von `bind` verwendet, `verify` ignoriert es vollständig** — die pro Anfrage geprüfte Identität stammt immer aus dem serverseitigen `SessionRecord` (die Fremdstandort-Historie aggregiert über `record.subject`), und die vom Aufrufer übergebene Angabe ist nicht vertrauenswürdig. `subject: ""` aus einer Middleware ist daher gültig (`bind` verlangt einen nicht-leeren Wert). Genau deshalb gehört **niemals** eine Nutzerkennung aus einem Request-Header hierher: Sie erreicht die Entscheidung heute nicht, aber ein künftiges Refactoring ist nicht daran gebunden.

## Modulpfade

| Modul | Pfad | Anzahl Detektoren |
|------|------|---------|
| Kern | `src/lib.rs` `result.rs` `scanner.rs` | — |
| Injection | `src/injection/` | 11 |
| Protokoll | `src/protocol/` | 11 |
| Daten | `src/data/` | 7 |
| Datei | `src/file/` | 3 |

## Leistung

Jeder Detektor hält seine Muster in einer statischen Tabelle `static PATTERNS: LazyLock<Vec<Regex>>`: Jede Regex wird beim ersten Zugriff innerhalb des Prozesses einmal kompiliert und danach bei jedem Aufruf wiederverwendet, ohne weiteren Kompilieraufwand. Ein Scan mit allen 32 Detektoren dauert pro Eingabe einige Dutzend Mikrosekunden; der Aufwand wächst mit der Anzahl der Detektoren und der Länge der Eingabe. Messen Sie den tatsächlichen Wert auf Ihrer eigenen Hardware und unter Ihrer Last. Geeignet für Szenarien mit hohem Durchsatz (API-Gateways, Log-Pipelines).
