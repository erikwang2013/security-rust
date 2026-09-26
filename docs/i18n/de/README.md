<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust

**🌐 [中文 (原文)](../../../README.md)**

In Rust geschriebene Angriffserkennungsbibliothek, die 32 Detektoren in vier Kategorien abdeckt: Injection-Angriffe, Protokollangriffe, Daten-/Serialisierungsangriffe sowie Datei-/Datenlecks. Keine externen Framework-Abhängigkeiten: Die Detektor-Kette arbeitet rein auf Strings, ergänzt um drei zustandsbehaftete Module (siehe unten).

Das Projekt-Haustier **甲哨 Sentri** ([`pet.svg`](../../pet.svg)) — 32 Panzerplatten für 32 Detektoren. Meldet alles, blockiert nichts.

---

## Projekt-Haustier: 甲哨 Sentri

<img src="../../pet.svg" alt="甲哨 Sentri — das Projekt-Haustier von security-rust" width="340">

Eine Wächterkrabbe mit Lupe und Schild. Die Figur ist keine Dekoration — sie ist das Design dieser Bibliothek, gezeichnet:

| Figur | Entsprechung im Design |
|------|---------|
| 4 Reihen × 8 Panzerplatten | 32 zustandslose Detektoren; die 4 Reihen = Injection / Protokoll / Daten / Datei |
| Lupe in der linken Schere | **Sehen** — `Detector::detect()` scannt nur; ein Treffer liefert genau einen Beleg |
| Schild in der rechten Schere (`已上报` — „gemeldet") | **Melden** — liefert `DetectionResult`, wirft keine Ausnahme, unterbricht keine Aufrufkette |
| Scheren, die nie zwicken | Die Entscheidung liegt beim Aufrufer; die einzige Ausnahme ist `SessionGuard`, der wirklich `Block` liefert |
| Monokel | Die Berufskrankheit des Auditors: jeder Befund trägt `matched_pattern` und `offset` und zeigt auf die Stelle im Original |
| `deps: regex ×1` auf dem Typenschild | Das Null-Abhängigkeits-Versprechen: `[dependencies]` enthält immer nur `regex` |

Leitspruch: **alles melden, nichts blockieren.**

Die Figur ist per `include_str!` in die Bibliothek eingebunden (keine Laufzeitkosten — ohne Nutzung wird sie nicht gelinkt); die ASCII-Version lässt sich direkt in ein Terminal oder Log schreiben:

```rust
println!("{}", security_rust::pet::ASCII);
```

---

## Projektstruktur

```
security-rust/
├── src/
│   ├── lib.rs              Detector-Trait (der einzige Vertrag), regex_detect-Helfer, Crate-Doku
│   ├── scanner.rs          Scanner / ScannerBuilder: montiert standardmäßig alle 32 Detektoren
│   ├── result.rs           DetectionResult / AttackCategory / Severity
│   ├── score.rs            Risikobewertung: Gewichtssumme + Stufen → RiskAssessment
│   ├── pet.rs              Die Figur des Projekt-Haustiers (NAME / TAGLINE / ASCII / SVG)
│   ├── injection/          11 Injection-Detektoren
│   ├── protocol/           11 Protokoll-Detektoren
│   ├── data/               7 Daten-Detektoren
│   ├── file/               3 Datei-Detektoren
│   ├── session/            SessionGuard + SessionStore (guard / store / geo)
│   └── throttle/           Throttle + ThrottleStore (guard / store)
├── tests/                  7 Integrationstests: Sitzung, Throttle, Lebenszyklus, Invarianten, Robustheit, End-to-End, Multi-Key-Throttle
├── examples/
│   ├── waf.rs              End-to-End-Pipeline (Scannen → Throttle → Sitzung → Maßnahme)
│   └── axum_middleware.rs  Referenz zur Einbindung der axum-Middleware
├── docs/
│   ├── API.md              Vollständige API-Referenz
│   ├── OWASP-COVERAGE.md   Abdeckungsmatrix gegen OWASP-Angriffsklassen
│   ├── pet.svg             Die Figur des Projekt-Haustiers
│   ├── diagrams/           Architektur-/Funktions-/Lebenszyklus-Diagramme (SVG)
│   ├── i18n/               READMEs und API-Dokumente in 12 Sprachen
│   └── ...                 Spenden-QR-Codes, Code-Review- und Testberichte
└── Cargo.toml              Die einzige Laufzeitabhängigkeit: regex
```

---

## Designphilosophie

### Warum „Erkennung" statt „Blockierung"

Diese Bibliothek ist als **reiner Eingabescanner** konzipiert — sie empfängt Strings und liefert strukturierte Erkennungsergebnisse. Sie ist an kein Web-Framework gebunden, führt keine HTTP-Request-/Response-Analyse durch und implementiert keine Echtzeit-Blockierung. Dadurch lässt sie sich in jede Kette einbetten: WAF-Regel-Engines, Log-Audits, vorgelagerte Validierung in API-Gateways, CLI-Sicherheits-Scan-Tools usw. Die Module `session`, `throttle` und `score` (siehe unten) gehen darüber hinaus: Sie halten Zustand bzw. aggregieren Signale, bleiben aber ebenfalls frei von Framework-Bindungen.

### Architekturprinzipien

- **Einzelverantwortung** — jeder Detektor kümmert sich um genau eine Angriffsart und hält intern kompilierte Regelsätze aus regulären Ausdrücken
- **Einheitliche Schnittstelle** — das `Detector`-Trait ist der einzige Vertrag aller Detektoren: `fn detect(&self, input: &str) -> Option<DetectionResult>`
- **Standardabdeckung** — `Scanner::default()` montiert mit einem Klick alle 32 Detektoren, einsatzbereit ohne Konfiguration
- **Optionale Konfiguration** — `Scanner::builder()` unterstützt bedarfsgerechte Anpassung; mit `.with_detector()` lassen sich Detektoren selektiv montieren

### Abwägungen

| Entscheidung | Wahl | Begründung |
|------|------|------|
| Regex vs. Parser | Regex | Geschwindigkeit hat im Erkennungsszenario Vorrang; Regex deckt verzerrte/Bypass-Muster besser ab |
| Ersttreffer vs. vollständige Erkennung | Vollständige Erkennung | Eine Eingabe kann mehrere Angriffsarten gleichzeitig auslösen; nichts darf übersehen werden |
| Null-Abhängigkeiten vs. Einführung von serde | Null-Abhängigkeiten | Nur `regex`; schnelle Kompilierung, kleine Größe |
| Detektor vs. zustandsbehaftetes Modul | Getrennt | `Detector::detect(&str)` bekommt nur einen String und kann die zusammengesetzte Eingabe „Token + Fingerabdruck + Position + Zeit" nicht ausdrücken; `session` / `throttle` stehen deshalb neben dem `Scanner` |
| fail-closed vs. fail-open | Authentifizierung fail-closed, Ratenbegrenzung fail-open | Eine Sitzungsentscheidung, die durchlässt, ist gleichbedeutend mit einer Umgehung und muss blockieren; die Ratenbegrenzung würde sonst alle Nutzer aussperren (Selbst-DoS), und das primäre Authentifizierungs-Gate blockiert weiterhin — die Entscheidung liegt beim Aufrufer |

---

## Architektur

<img src="../../diagrams/architecture.svg" alt="security-rust Architektur: Aufrufer → Erkennungsschicht → Bewertungsschicht → Wächter-Schicht → Speicherabstraktion" width="900">

Fünf Schichten von oben nach unten: **Aufrufer** (WAF / Gateway / Audit / CLI) → **Erkennungsschicht** (`Scanner` mit `Vec<Box<dyn Detector>>`, 32 Detektoren in vier Kategorien) → **Bewertungsschicht** (`score::assess`) → **Wächter-Schicht** (`SessionGuard` / `Throttle`, jeweils an ein Store-Trait gebunden) → **Speicherabstraktion** (eingebautes `MemoryStore`, Redis vom Aufrufer implementiert).
*(Die Beschriftungen im Diagramm sind auf Chinesisch; die Bezeichner sind API-Namen.)*

Das `Detector`-Trait ist der einzige Vertrag der Erkennungsschicht: `fn detect(&self, input: &str) -> Option<DetectionResult>`. `session`, `throttle` und `score` implementieren es nicht — ihre Eingabe ist kein einzelner String (Token + Fingerabdruck + Position + Zeit), oder sie konsumieren Scan-Ergebnisse statt der Roh-Eingabe — und antworten deshalb eigenständig (siehe unten). Der rote Rückweg rechts markiert die Grenze dieser Bibliothek: **das Urteil geht zur Ausführung zurück an den Aufrufer**; die Bibliothek selbst berührt die Anfrage nicht.

### Zuständigkeiten der Module

| Modul | Pfad | Anzahl Detektoren | Zuständigkeit |
|------|------|---------|------|
| Kern | `src/lib.rs` `result.rs` `scanner.rs` | — | `Detector`-Trait, `DetectionResult`, `Scanner`/`ScannerBuilder` |
| Injection | `src/injection/` | 11 | XSS, SQL-Injection, Command-Injection, NoSQL, LDAP, XPATH, JNDI, SSI, GraphQL, SSTI, Format-String |
| Protokoll | `src/protocol/` | 11 | SSRF, XXE, Header-Injection, Host-Header-Angriffe, Request Smuggling, Open Redirect, CORS, WebSocket, DNS-Rebinding, Log4Shell, HTTP-Parameter-Pollution |
| Daten | `src/data/` | 7 | PHP-Deserialisierung, CSV-Formel-Injection, E-Mail-Header-Injection, JWT-Angriffe, Prototype Pollution, Formel-Injection, ReDoS |
| Datei | `src/file/` | 3 | Path Traversal, bösartige Datei-Uploads, Leck sensibler Daten |

### Struktur des Erkennungsergebnisses

`DetectionResult` liefert strukturiert sechs Felder: `attack_type`, `category`, `severity`, `matched_pattern`, `offset`, `message`. Die vollständige Definition findest du in der [API-Referenz](./API.md).

---

## Implementierte Funktionen

<img src="../../diagrams/features.svg" alt="security-rust Funktionsübersicht: Injection 11, Protokoll 11, Daten 7, Datei 3, dazu drei zustandsbehaftete Module" width="900">

Alle 32 Detektoren werden nach Kategorie montiert und sind über `Scanner::default()` ohne Konfiguration vollständig aktiv. Die folgenden Tabellen listen auf, was jeder einzelne abdeckt, samt Schweregrad. Der Schweregrad beschreibt einen einzelnen Treffer; das aggregierte Gesamtrisiko liefert `Scanner::assess()`.
*(Die Beschriftungen im Diagramm sind auf Chinesisch; die Bezeichner sind API-Namen.)*

### Injection-Angriffe (11 Detektoren)

| Detektor | Abgedeckte Muster | Schweregrad |
|--------|---------|--------|
| **xss** | `<script>`, Event-Handler wie `onerror=`, `javascript:`-Pseudo-Protokoll, `<svg>`/`<iframe>`-Tags, CSS `expression()`, `eval()`, `document.cookie` | Critical |
| **sql_injection** | `UNION SELECT`, verzögerte Injection mit `sleep()`/`benchmark()`/`pg_sleep()`, Enumeration von `information_schema`, Stored Procedures `exec sp_`/`xp_`, Boolean-Blind-Injection-Muster `' OR '1'='1`, `LOAD_FILE()`/`INTO OUTFILE` | Critical |
| **command_injection** | Backtick-Befehle, `$()`-Subshells, Verkettung über Pipe-Symbole, Reverse Shell über `/dev/tcp`, PHP-Funktionen `passthru()`/`shell_exec()`/`system()`, Aufrufe von `cmd.exe`/`powershell` | Critical |
| **nosql_injection** | MongoDB-Operatoren `$ne`/`$gt`/`$regex`/`$where`, `$or`-Injection, Authentifizierungs-Bypass `{"$gt": ""}` | Critical |
| **ldap_injection** | Filter-Operatoren `(&` `(\|` `(!`, Attribut-Enumeration `*(cn=`, `objectClass`/`uid`-Injection | High |
| **xpath_injection** | Boolean-Bypass `' or '1'='1`, Funktions-Injection `' or true()`, Knoten-Traversierung `'] \| '` | High |
| **jndi_injection** | `${jndi:ldap://`, Obfuskation `${lower:j}`, Obfuskation `${upper:j}`, Obfuskation mit leerem String `${::-j}`, Umgebungsvariablen-Nachschlag `${env:}`, Systemeigenschaften `${sys:}` | Critical |
| **ssi_injection** | Befehlsausführung `<!--#exec cmd=`, Datei-Inklusion `<!--#include file=`, Variablen-Ausgabe `<!--#echo var=`, Datei-Informationen `<!--#fsize`/`<!--#flastmod` | High |
| **graphql_injection** | Introspection-Abfragen `__schema`/`__type`, tief verschachteltes DoS (≥5 Ebenen) | Medium |
| **ssti** | Jinja2 `{{ }}` / FreeMarker `${ }` — **Auswertung innerhalb der Delimiter** (`{{7*7}}`, `${7*7}`, `{{config`, `${T(java.lang.Runtime)}`), ERB `<%=` `<%@`, Velocity `#set()`, Python-Escape-Ketten `__mro__`/`__subclasses__()`/`__globals__`/`__builtins__`/`__class__`/`__dict__`; die Delimiter allein sind kein Signal, ein reiner Platzhalter wie `${x}` wird nicht gemeldet | Critical |
| **format_string** | `%n`-Schreibspezifizierer (auch mit Längenmodifikatoren), überlange Breitenangaben `%123456d`, gehäufte `%x`/`%p`/`%s`-Spezifizierer (Format-String-Leak / Speicherkorruption) | Medium |

### Protokoll- und Request-Angriffe (11 Detektoren)

| Detektor | Abgedeckte Muster | Schweregrad |
|--------|---------|--------|
| **ssrf** | Cloud-Metadaten `169.254.169.254`, RFC1918-interne IPs (10.x, 172.16-31.x, 192.168.x), `127.x`-Loopback, `::1`-IPv6-Loopback, `0.0.0.0`, gefährliche Protokolle `gopher://`/`dict://`/`ftp://`/`file://` | Critical |
| **xxe** | Entitäts-Deklarationen `<!ENTITY`, externe Referenzen `SYSTEM`/`PUBLIC`, Parameter-Entitäten `%`, DTD-Deklaration `<!DOCTYPE` | Critical |
| **header_injection** | URL-kodiertes CRLF `%0d%0a`, rohe CRLF-Injection `\r\n` | High |
| **host_header** | Mehrfache Host-Header-Injection, Vergiftung über `X-Forwarded-Host`/`X-Original-URL`/`X-Rewrite-URL`, CRLF im Host-Header | High |
| **request_smuggling** | Doppelte `Transfer-Encoding`-Header, Smuggling über `Content-Length: 0`, Obfuskation des Chunked-Abschlusses `\r\n0\r\n` | High |
| **open_redirect** | Protokoll-relative URLs `//evil.com`, Sprünge über Pseudo-Protokolle `javascript:`/`data:text/html` | Medium |
| **cors** | `Access-Control-Allow-Origin: null`, `Origin: null` (das kanonische Indiz für Sandbox-iframes und CSWSH) sowie `Access-Control-Allow-Origin: *` **zusammen mit** `Access-Control-Allow-Credentials: true`. Einzeln sind beide für öffentliche APIs und statische Assets normal und werden nicht gemeldet | Medium |
| **websocket** | `Origin: null` zusammen mit einem WebSocket-Upgrade (CSWSH), `ws://` auf Loopback-/private/Link-Local-Adressen (inkl. Cloud-Metadaten-Endpunkt `169.254.169.254`) | High |
| **dns_rebinding** | Host-Header mit internen IPs `127.x`/`10.x`/`192.168.x`/`172.16-31.x`, `localhost`, `::1`, `0.0.0.0` | High |
| **log4shell** | Lookup-Obfuskation `${lower:j}`/`${upper:j}`, Obfuskation mit leerem String `${::-j}`, verschachtelte Lookups `${${...}:...}`, URL-kodierte Variante `%24%7b...%7d...ndi` | Critical |
| **hpp** | Vermischung von Trennzeichen im Query-String `&a=1;b=2` und `;a=1&b=2` (Parameter-Pollution durch abweichende Parser-Semantik) | Medium |

### Daten- und Serialisierungsangriffe (7 Detektoren)

| Detektor | Abgedeckte Muster | Schweregrad |
|--------|---------|--------|
| **deserialization** | PHP-serialisierte Objekte `O:Zahl:`/`C:Zahl:`, Arrays `a:Zahl:{`, `unserialize()`-Aufrufe, magische Methoden wie `__wakeup`/`__destruct`/`__toString` | Critical |
| **csv_injection** | Formelzeichen `=`/`+`/`-`/`@` am Zellenanfang (Tabulator und Wagenrücklauf sind **Trennzeichen**, kein Formelbeginn), ein `=` unmittelbar nach einem `,`/`;`/`\t`-Trennzeichen, DDE (Dynamic Data Exchange), Befehls-Pipes `cmd\|`, `@SUM()`-Funktion | Medium |
| **mail_header** | Blindkopie-Injection `Bcc:`/`Cc:`, mehrfache Absender `From:`, MIME-Header-Injection `MIME-Version:`/`Content-Type: multipart`, Manipulation der `boundary=`-Grenze | Medium |
| **jwt_attack** | Bypass mit leerem Algorithmus `alg: none`, Path-Traversal-Injection über `kid`, leeres Signatur-Segment, leeres Payload-Segment | High |
| **prototype_pollution** | Prototype-Chain-Pollution `__proto__`/`constructor.prototype`, Property-Kapern über `__defineGetter__`/`__defineSetter__`/`__lookupGetter__`/`__lookupSetter__` | High |
| **formula_injection** | Formelzeichen am Feldanfang mit Befehls-Pipe `=cmd\|`, gefährliche Tabellenfunktionen `HYPERLINK`/`IMPORTXML`/`IMPORTDATA`/`IMPORTRANGE`/`WEBSERVICE`/`RTD`/`EXEC`, Datenabfluss über `\|` + Zellbezug `A0`, `DDE(`-Aufrufe, `@`-Funktionen | High |
| **redos** | Katastrophales Backtracking: verschachtelte Quantifizierer `(a+)+`/`(a{2,})+`, überlappende Alternativen `(a\|ab)+`, Quantifizierer über `\w`/`\d`/`.`-Gruppen | Medium |

### Dateien und sensible Daten (3 Detektoren)

| Detektor | Abgedeckte Muster | Schweregrad |
|--------|---------|--------|
| **path_traversal** | Directory Traversal `../`/`..\\`, URL-kodierter Bypass `%2e%2e`, Protokoll-Wrapper `php://filter`/`php://input`/`phar://`/`zip://`/`data://`/`expect://`/`glob://`, Null-Byte-Terminierung `%00` | Critical |
| **upload** | PHP-Tags `<?php`/`<?=`, ASP-Tags `<%@`/`<%=`, Backdoor-Muster `eval($_`/`system($_`/`exec($_`/`passthru($_`, Superglobals `$_GET`/`$_POST`/`$_REQUEST`/`$_SERVER`, Kodierungs-Bypass mit `base64_decode()` | Critical |
| **data_leak** | 16-stellige Kreditkarten-PAN (Visa/MasterCard/AmEx/Discover/JCB/Diners), AWS Access Keys `AKIA...`, PEM-Private-Key-Header `-----BEGIN`, OpenAI/LLM-API-Keys `sk-...`, Datenbank-Verbindungsstrings `mongodb://`/`mysql://`/`postgresql://`/`redis://`/`jdbc:`, JWT-Tokens | Critical |

---

## Zustandsbehaftete Module

`session`, `throttle` und `score` sind **keine** `Detector`-Implementierungen. `session` und `throttle` sind zustandsbehaftet und identitätsbezogen — `Detector::detect(&self, input: &str)` kann eine zusammengesetzte Eingabe aus Token, Fingerabdruck, Position und Zeit nicht ausdrücken. Sie treten deshalb neben die Detektor-Kette, nicht in sie.

| Modul | Typ | Aufgabe |
|------|------|------|
| `session` | `SessionGuard<S: SessionStore>` | Sitzungssicherheit: Client-Hijacking, Datenmanipulation, Anmeldung von ungewöhnlichem Ort, Token-Sitzungen. Methoden `bind`/`verify`/`revoke`/`revoke_all`/`rotate`; `Decision { Allow, Challenge, Block }` + `SessionThreat`; `SessionConfig` (`ttl_secs` 3600, `impossible_travel_kmh` 900.0, `timestamp_skew_secs` 300); Trait `SessionStore` + `MemoryStore` |
| `throttle` | `Throttle<S: ThrottleStore>` | Ratenbegrenzung und Sperre: gleitendes Fenster, Schwellwert-Sperre, Kontosperrung. Methoden `check`/`check_any`/`record_failure`/`record_success`/`reset`/`purge_expired`; `ThrottleDecision { Allow { remaining }, Banned { until }, Unavailable }`; `ThrottleConfig` (`threshold` 5, `window_secs` 60, `ban_secs` 900); `record_failure` gibt `ThrottleOutcome` (`Allow`/`Banned`) zurück — ohne `Unavailable` |
| `score` | `RiskLevel`, `RiskAssessment`, `Scanner::assess()` | Risikobewertung: aggregiert einzelne Signale niedriger Schwere zu einer messbaren Größe. `RiskLevel { None, Low, Medium, High, Critical }` |

**Asymmetrisches Fehlerverhalten ist Absicht.** `SessionGuard` gibt bei einem Speicherfehler `Decision::Block` (`StoreUnavailable`) zurück — fail-closed, es wird nie durchgelassen. `Throttle` ist die bewusste Ausnahme: Ratenbegrenzung ist Defense-in-Depth und kein primäres Authentifizierungs-Gate, deshalb liefert ein Backend-Ausfall `ThrottleDecision::Unavailable` statt `Banned` — alle Nutzer auszusperren wäre ein Selbst-DoS. Die Entscheidung liegt beim Aufrufer.

**Weiterhin keine neuen Abhängigkeiten:** Die Liste bleibt bei `regex`. Der Preis: Token und Signatur liefert der Aufrufer, Positionen parst der Aufrufer. Beide Module abstrahieren ihren Speicher über ein Trait — für den Mehrinstanz-Betrieb genügt eine Implementierung von `SessionStore`/`ThrottleStore` auf Redis.

---

## Lebenszyklus

<img src="../../diagrams/lifecycle.svg" alt="security-rust drei Lebenszyklen: Scan, Sitzung, Throttle" width="900">

Drei Lebenszyklen laufen unabhängig voneinander; sie treffen sich nur im Request-Handler des Aufrufers:
*(Die Beschriftungen im Diagramm sind auf Chinesisch; die Bezeichner sind API-Namen.)*

| Lebenszyklus | Beginn | Ende | Zustandsablage |
|---------|------|------|---------|
| **Scan** | `Scanner::scan(&str)` | `Vec<DetectionResult>` → `score::assess` → `RiskAssessment` | Zustandslos, jeder Aufruf ist eigenständig |
| **Sitzung** | `SessionGuard::bind()` schreibt einen `SessionRecord` | pro Request `verify()` → `SessionVerdict` ⇒ `Allow` / `Challenge` / `Block` | `SessionStore` (eingebaut: `MemoryStore`) |
| **Throttle** | `Throttle::check_any(&[keys])` | `Allow{remaining}` / `Banned{until}` / `Unavailable` | `ThrottleStore` (eingebaut: `MemoryThrottleStore`) |

Zwei Grenzfälle, die leicht danebengehen:

- **`remaining == 0` heißt: diese Anfrage muss abgelehnt werden** — das Kontingent ist aufgebraucht, nicht „noch ein Versuch". Beim Schreiben von `X-RateLimit-*` nicht verdrehen.
- **Speicherfehler werden gegenläufig behandelt**: `SessionGuard` ist fail-closed (`StoreUnavailable` ⇒ `Block`, es wird nie durchgelassen — sonst tauscht ein Angreifer, der einen Backend-Ausfall provoziert, eine ganze Klasse von Prüfungen aus); `Throttle` ist fail-open (`Unavailable` geht an den Aufrufer, denn alle Nutzer bei einem Backend-Aussetzer auszusperren wäre ein Selbst-DoS, und das Hauptgate `SessionGuard` blockiert weiterhin). Das ist eine bewusst festgeschriebene Entscheidung, kein fehlender Fallback.

---

## Verwendung

Sofort einsatzbereit ohne Konfiguration:

```rust
use security_rust::Scanner;

let scanner = Scanner::default();
let results = scanner.scan("<script>alert('xss')</script>");
// [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
```

Die Risikobewertung fasst die Trefferliste zu einer einzigen Stufe zusammen, damit gestapelte Signale niedriger Schwere nicht stillschweigend untergehen:

```rust
let assessment = scanner.assess("=cmd|' /C calc'!A0 `cat /etc/passwd` ../../../etc/passwd");
// assessment.level   >= RiskLevel::High
// assessment.results >= 3
// assessment.score   — gewichtete Rohpunkte
```

Die vollständige API-Referenz (Installation, selektive Scans, benutzerdefinierte Konfiguration, Risikobewertung, Schweregrad-Anzeige, Sitzungssicherheit, Ratenbegrenzung und Sperre, Leistung) findest du in der [API-Referenz](./API.md).

### Sitzungssicherheit (`session`)

```rust
use security_rust::session::{Decision, MemoryStore, RequestContext, SessionConfig, SessionGuard};

let guard = SessionGuard::new(MemoryStore::new(), SessionConfig::default());

let login = RequestContext {
    token: "tok-abc",
    subject: "u-1",
    fingerprint: "ip=1.2.3.4|ua=curl",   // Client-Fingerabdruck, beim Login gebunden
    location: Some("CN-BJ"),
    coords: Some((39.9042, 116.4074)),
    signature: None,                      // MAC wird vom Aufrufer signiert
    at: None,
};

// Login: Sitzung anlegen + Fingerabdruck binden + Position erfassen; ein fremder Ort
// beeinflusst nur das Verdict, er blockiert den Login nicht
guard.bind(&login, 1_700_000_000).unwrap();

// Prüfung pro Request: derselbe Token, ein anderer Fingerabdruck ⇒ Client-Hijacking
let verdict = guard.verify(&RequestContext { fingerprint: "ip=5.6.7.8|ua=curl", ..login }, 1_700_000_010);

match verdict.decision {
    Decision::Allow => { /* durchlassen */ }
    Decision::Challenge => { /* durchlassen, aber zweite Prüfung verlangen: fremder Ort, Zeitabweichung, unerwartete Signatur */ }
    Decision::Block => { /* ablehnen */ }
}
```

### Ratenbegrenzung und Sperre (`throttle`)

```rust
use security_rust::throttle::{MemoryThrottleStore, Throttle, ThrottleConfig, ThrottleDecision};

let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());
let key = "acct:u-1"; // den key konstruiert und normalisiert der Aufrufer — nie Roh-Eingaben als key verwenden
let now = 1_700_000_000;

// Echte Anfragen haben zwei Dimensionen: IP und Konto. check_any fragt beide in einem Aufruf ab
// und führt sie nach Strenge zusammen
match throttle.check_any(&["ip:1.2.3.4", key], now) {
    // remaining lässt sich in X-RateLimit-* schreiben; **remaining == 0 heißt: diese Anfrage ablehnen**
    ThrottleDecision::Allow { remaining } => { /* Restkontingent remaining */ }
    // ab now >= until gilt die Sperre als aufgehoben
    ThrottleDecision::Banned { until } => { /* gesperrt, Entsperrung bei until */ }
    // Backend-Ausfall: dieses Modul entscheidet nicht für den Aufrufer (empfohlen: durchlassen + Alarm)
    ThrottleDecision::Unavailable => { /* Ratenbegrenzungs-Backend nicht verfügbar */ }
}

// Fehlgeschlagene Authentifizierung zählen: ab threshold wird gesperrt. Liefert ThrottleOutcome
// (zwei Zustände); ein Speicherfehler geht als Err zurück — kein toter Code für einen
// Unavailable-Zweig, der nie ausgeführt wird
let _ = throttle.record_failure(key, now);
```

---

## Entwicklung

```bash
# Build
cargo build --release

# Tests (494: 365 Unit-Tests, 128 Integrationstests, 1 Dokumentationstest)
cargo test

# End-to-End-Pipeline-Beispiel (Scannen → Throttle → Sitzung → Maßnahme)
cargo run --example waf

# Lint
cargo clippy -- -D warnings
```

---

## Spenden / Unterstützung

Wenn dir dieses Projekt hilft, freuen wir uns über eine Spende (freiwillig).

| Alipay | WeChat Pay |
|--------|---------|
| ![Alipay](./alipay.png) | ![WeChat Pay](./weixinpay.png) |

### Internationale Überweisung (Auslandsüberweisung)

**Empfängerinformationen**
- Name des Empfängers: WANG KEXUN
- Kontonummer des Empfängers: 881015918251

**Empfängerbank**
- ZA Bank SWIFT-Code: AABLHKHHXXX
- Bankname: ZA Bank Limited
- Bankleitzahl: 387
- Bankadresse: Core F, Cyberport 3, 100 Cyberport Road, Hong Kong

**Korrespondenzbank für grenzüberschreitende Überweisungen (falls erforderlich)**

Bitte beachte: Dies sind die Angaben der Korrespondenzbank (Zwischenbank) für grenzüberschreitende Überweisungen, nicht die der Empfängerbank. Frage deine überweisende Bank, ob Angaben zur Korrespondenzbank erforderlich sind.

Die Korrespondenzbank für Überweisungen in Hongkong-Dollar (HKD), chinesische Renminbi (CNY) und US-Dollar (USD) ist Citibank:
- Bankname: Citibank N.A. Hong Kong
- SWIFT-Code: CITIHKHXXXX
- Bankleitzahl: 006
- Filialname: Hong Kong Branch
- Filialnummer: 391
- Bankadresse: Citibank Tower, Citibank Plaza, 3 Garden Road, Central, Hong Kong

Für Überweisungen in anderen Währungen ist die Korrespondenzbank BNY Mellon:
- Bankname: THE BANK OF NEW YORK MELLON
- SWIFT-Code: IRVTUS3NXXX
- Bankadresse: THE BANK OF NEW YORK MELLON, 240 GREENWICH STREET, NEW YORK, United States

---

## Lizenz

MIT — Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
