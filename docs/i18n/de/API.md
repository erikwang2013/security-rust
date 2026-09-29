<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust API-Referenz

[中文](../../../README.md) | [English](../en/API.md) | [한국어](../ko/API.md) | [Русский](../ru/API.md) | [Français](../fr/API.md) | [Español](../es/API.md) | [Português](../pt/API.md) | [हिन्दी](../hi/API.md) | [العربية](../ar/API.md) | [বাংলা](../bn/API.md) | [Bahasa Indonesia](../id/API.md) | [日本語](../ja/API.md) | [Deutsch (本页)](./API.md)

---

## Kern-Trait

### `Detector`

Der einzige Vertrag aller Detektoren:

```rust
pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
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

## Zwei Stufen: starke und schwache Signale

18 der 32 Detektoren teilen ihre Muster in zwei Stufen (die Statics `STRONG_PATTERNS` / `WEAK_PATTERNS` im Quelltext). Die Feldstruktur von `DetectionResult` bleibt unverändert; geändert hat sich der Wert von `severity`:

| Stufe | Kriterium | `severity` | Überschreitet ein einzelner Treffer die Ablehnungsgrenze? |
|------|------|-----------|------------------|
| **Stark** | Die Form selbst kann nur von einem Angriff stammen | Der erklärte Grad des Detektors | Ja |
| **Schwach** | Das Token *kommt vor* — in normalen Inhalten ist es allgegenwärtig | Immer `Severity::Low` (5 Punkte) | **Nein** |

Derselbe Detektor, derselbe `attack_type`, nur `severity` unterscheidet sich; `detect()` probiert zuerst die starke Stufe und fällt dann auf die schwache zurück, daher liefert **jeder Detektor höchstens ein Ergebnis**. Schwache Signale werden weiterhin erkannt und nicht stillschweigend verworfen.

`DetectionResult` selbst unterscheidet die Stufen nicht — ob ein Treffer stark oder schwach ist, erkennt man an `severity == Severity::Low` (die schwache Stufe ist die einzige Quelle, die `Low` meldet). Die Referenz-Pipeline lehnt bei 40 Punkten ab (`risk.level >= RiskLevel::High`, siehe [`examples/waf.rs:166`](../../../examples/waf.rs)); ein einzelnes schwaches Signal ist 5 Punkte wert und erreicht diesen Zweig nicht.

Den Angriff hinter schwachen Signalen sieht man, indem `assess()` die Treffer mehrerer Detektoren stapelt:

```rust
let scanner = Scanner::default();

// Drei schwache Signale aus drei verschiedenen Detektoren — erst der Stapel erreicht Medium (15 Punkte), noch unter High
let a = scanner.assess("<script src=\"/app.js\"></script>\n../config\n__proto__");
assert_eq!(a.results, 3);
assert_eq!(a.score, 15);
assert_eq!(a.level, RiskLevel::Medium);
```

Beispiele für herabgestufte Formen (die vollständige Liste steht in den `WEAK_PATTERNS` der einzelnen Detektoren): `<script src=...>`, ein einstufiges `../`, `-2` am Zeilenanfang, ein nacktes `__proto__`, `${env:}`, `X-Forwarded-Host`, `Host: localhost`, eine nackte `10.0.0.5`, `//evil.com`, `information_schema`.

Entscheidend ist die **Form**, nicht der Dateiname: Bei demselben `../` meldet eine einzelne Ebene (`../x`) `Low` und melden mehrere Ebenen (`../../`) `Critical` ([`src/file/path_traversal.rs`](../../../src/file/path_traversal.rs)). Wie hoch die einzelnen Detektoren reichen, steht in den Tabellen unten und in den Funktionstabellen des [README](./README.md).

## Scanner

### Installation

```toml
[dependencies]
security-rust = "2.1.1"
```

### Schnellstart

```rust
use security_rust::Scanner;

fn main() {
    // Null Konfiguration: montiert alle 32 Detektoren
    let scanner = Scanner::default();

    // Scannt die Eingabe und liefert alle erkannten Angriffe (höchstens ein Ergebnis pro Detektor)
    let results = scanner.scan("<img src=x onerror=alert(1)>");

    for r in &results {
        println!("[{}] {} — offset: {}, pattern: {}",
            r.severity, r.message, r.offset, r.matched_pattern);
    }
    // Ausgabe:
    // [CRITICAL] XSS cross-site scripting detected — offset: 11, pattern: onerror=

    // Ein schwaches Signal nutzt denselben Detektor und denselben attack_type, meldet aber Low
    let weak = scanner.scan("<script src=\"/app.js\"></script>");
    // [LOW] XSS tag present (weak signal) — offset: 0, pattern: <script>
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
    Decision, MemoryStore, MemoryThrottleStore, RequestContext, Scanner,
    SessionConfig, SessionGuard, SessionVerdict,
    Throttle, ThrottleConfig, ThrottleDecision, ThrottleOutcome,
};

let now = 1_700_000_000u64;
let ctx = RequestContext {
    token: "tok-1", subject: "user-42", fingerprint: "ip=203.0.113.7|ua=curl",
    location: Some("CN-BJ"), coords: Some((39.9042, 116.4074)), signature: Some("mac-abc"), at: Some(now),
};

// Sitzungsschutz — fail-closed: bei Speicherfehler Decision::Block
let sessions = SessionGuard::new(MemoryStore::new(), SessionConfig::default());
let verdict: SessionVerdict = sessions.verify(&ctx, now);
if verdict.decision == Decision::Block {
    // ablehnen
}

// Ratenbegrenzung — Defense-in-Depth: bei Backend-Ausfall Unavailable, nicht Banned
let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());
match throttle.check("acct:user-42", now) {
    ThrottleDecision::Allow { remaining: 0 } => { /* ablehnen: Kontingent erschöpft */ }
    ThrottleDecision::Allow { .. } => { /* durchlassen */ }
    ThrottleDecision::Banned { until } => { /* gesperrt bis `until` */ }
    ThrottleDecision::Unavailable => { /* selbst entscheiden */ }
}

// Mehrere Dimensionen zusammenführen (z. B. IP + Konto): das strengste Ergebnis gewinnt
let merged = throttle.check_any(&["ip:203.0.113.7", "acct:user-42"], now);
match throttle.record_failure("acct:user-42", now) {
    Ok(outcome) => { /* ThrottleOutcome: Allow { remaining } | Banned { until } */ }
    Err(_) => { /* Speicherfehler */ }
}

// Risikobewertung: Einzelsignale zu einer messbaren Größe aggregieren
let risk = Scanner::default().assess("<script>alert('xss')</script>");
```

| Element | Signatur / Feld |
|------|------|
| `SessionGuard::bind` | `fn bind(&self, ctx: &RequestContext, now: u64) -> Result<SessionVerdict, SessionError>` |
| `SessionGuard::verify` | `fn verify(&self, ctx: &RequestContext, now: u64) -> SessionVerdict` |
| `SessionGuard::revoke` / `revoke_all` | `fn revoke(&self, token: &str) -> Result<(), StoreError>` / `fn revoke_all(&self, subject: &str) -> Result<usize, StoreError>` |
| `SessionGuard::rotate` | erneuert das Token einer Sitzung |
| `SessionGuard::purge_expired` | löscht abgelaufene Sitzungen und die Login-Historie ruhender Subjects. **Der Rückgabewert zählt nur Sitzungen**, nicht die zurückgewonnene Login-Historie |
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

**Die Zahl der Subjects ist beim In-Memory-Backend nach oben offen.** `MemoryStore` begrenzt die Login-Historie je Subject auf `MAX_LOGINS_PER_SUBJECT` = 10, **nach oben offen ist die Zahl der Subjects** (`Mutex<HashMap>`, kein Hintergrund-Thread, Einträge wachsen nur). Lang laufende Prozesse sollten `purge_expired` in Abständen in der Größenordnung von `ttl_secs` aufrufen: Es löscht Sitzungen mit `expires_at <= now` sowie die gesamte Login-Historie jedes Subjects, dessen letzter Login vor `now - LOGIN_HISTORY_KEEP_SECS` (7 Tage) liegt. **Der Rückgabewert zählt nur Sitzungen**, nicht die zurückgewonnene Login-Historie. Die Historie eines ruhenden Subjects zurückzugewinnen kostet diesen bei der nächsten Anmeldung eine Fremdstandort-/Impossible-Travel-Prüfung — das ist ein falsch-negatives und kein falsch-positives Ergebnis; danach wird die Historie sofort neu aufgebaut.

## Modulpfade

| Modul | Pfad | Anzahl Detektoren |
|------|------|---------|
| Kern | `src/lib.rs` `result.rs` `scanner.rs` | — |
| Injection | `src/injection/` | 11 |
| Protokoll | `src/protocol/` | 11 |
| Daten | `src/data/` | 7 |
| Datei | `src/file/` | 3 |
| Haustier | `src/pet.rs` | — |

## Bekannte Grenzen

Die folgenden Punkte sind **bekannte, bewusst beibehaltene** Grenzen und keine Mängel, die auf eine Korrektur warten. Vor Änderungen bitte die Begründung lesen — jeder Punkt beruht auf Messungen, und jeder hat bereits einen Versuch abgewehrt, ihn zu verschärfen.

### `dns_rebinding` meldet nur, es blockiert nicht

Sein Kriterium lautet „im `Host:`-Header steht eine interne Adresse" — und genau diese Form hat jeder Pod-zu-Pod-Aufruf in k8s (`Host: 10.244.1.5:8080`), jede lokale Entwicklung (`Host: localhost:8000`) und jede Anfrage im Docker-Containernetz (`172.18.0.2`). Echtes Rebinding ist „öffentlicher Domainname + Auflösungsergebnis zeigt nach innen", und der `Host`, den der Browser sendet, ist genau dieser öffentliche Name — **in einer einzelnen Zeichenkette ist keine Auflösungshistorie zu sehen**, die von diesem Detektor geprüfte Form deckt sich also nicht mit der Angriffsform, und es gibt keine Richtung, in die sich das verschärfen ließe. Deshalb ist der Detektor durchgehend schwach und meldet immer `Low`; egal wie viele Treffer sich stapeln, allein überschreitet er die Ablehnungsgrenze nie. Der Schutz gehört hinter die Namensauflösung, in den Vergleich der resultierenden IP — nicht in die String-Ebene.

### Diese Bibliothek kann ihren eigenen Quelltext, ihre Tests und ihre Doku nicht scannen

Die Obergrenze des Signatur-Scanners: gemessen an diesem Repository überschreiten 78 von 298 Dateien die Ablehnungsgrenze, und sie enthalten **konstruktionsbedingt** alle Angriffsstrings — Testlasten, die Regex-Literale der Detektor-Quelltexte selbst und die README- und OWASP-Tabellen, die diese Muster auflisten. Ein README wird nicht dadurch mangelhaft, dass es `(a+)+` auflistet. Wer die eigenen Artefakte scannen will, muss diesen Korpus zuerst ausschließen — oder ein anderes Kriterium wählen.

### `upload` meldet `<%@` / `<?php` überall als Critical

Der Vertrag dieses Detektors lautet „**dieser Blob ist serverseitig ausführbarer Code**" — Vorhandensein genügt, deshalb gibt es keine Stufenteilung. Eine JSP-Seite und eine JSP-Webshell teilen ihre Präambel byteweise (`<%@ page language="java" … %>` und `<%@ page import="java.io.*" %>` sind dieselbe Form); `<%@`/`<%=` herabzustufen hieße, Webshells unter die Ablehnungsgrenze fallen zu lassen — Löschen unter anderem Namen. Der Preis: Auch das Scannen einer **gerade ausgelieferten** Seite (statt einer hochgeladenen Datei) trifft; das ist eine falsche Eingabedomäne.

### `path_traversal` meldet `(?:\.\./){2,}` als Critical

Ein tiefer relativer Pfad in einem Monorepo (`from '../../../shared/domain'`) trifft. Es wird nicht weiter verschärft, weil die einzige Einschränkung, die ihn von einem Angriff trennt, eine Liste von Zieldateinamen ist (`../etc/passwd` und Verwandte) — und die deckt nur Systemdateien ab: Der Angreifer wählt einfach ein anderes LFI-Ziel.

## Leistung

Jeder Detektor hält seine Muster in einer statischen Tabelle `static PATTERNS: LazyLock<Vec<Regex>>`: Jede Regex wird beim ersten Zugriff innerhalb des Prozesses einmal kompiliert und danach bei jedem Aufruf wiederverwendet, ohne weiteren Kompilieraufwand. Ein Scan mit allen 32 Detektoren dauert pro Eingabe einige Dutzend Mikrosekunden; der Aufwand wächst mit der Anzahl der Detektoren und der Länge der Eingabe. Messen Sie den tatsächlichen Wert auf Ihrer eigenen Hardware und unter Ihrer Last. Geeignet für Szenarien mit hohem Durchsatz (API-Gateways, Log-Pipelines).
