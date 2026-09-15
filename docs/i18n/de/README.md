<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust

**🌐 [中文 (原文)](../../README.md)**

In Rust geschriebene Angriffserkennungsbibliothek, die 32 Detektoren in vier Kategorien abdeckt: Injection-Angriffe, Protokollangriffe, Daten-/Serialisierungsangriffe sowie Datei-/Datenlecks. Keine externen Framework-Abhängigkeiten: Die Detektor-Kette arbeitet rein auf Strings, ergänzt um drei zustandsbehaftete Module (siehe unten).

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

---

## Architektur

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

## Verwendung

Sofort einsatzbereit ohne Konfiguration:

```rust
use security_rust::Scanner;

let scanner = Scanner::default();
let results = scanner.scan("<script>alert('xss')</script>");
// [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
```

Die vollständige API-Referenz (Installation, selektive Scans, benutzerdefinierte Konfiguration, Schweregrad-Anzeige, Leistung) findest du in der [API-Referenz](./API.md).

---

## Entwicklung

```bash
# Build
cargo build --release

# Tests (462 Tests: 354 Unit-, 46 Integrations-, 62 Modul-Tests)
cargo test

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
