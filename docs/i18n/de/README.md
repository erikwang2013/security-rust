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

### Zwei Stufen: starke und schwache Signale

Ein Detektor meldet **nicht** jeden Treffer mit seinem erklärten Schweregrad. 18 der 32 Detektoren teilen ihre Muster in zwei Stufen (die Statics `STRONG_PATTERNS` / `WEAK_PATTERNS` im Quelltext):

| Stufe | Kriterium | Gemeldeter Schweregrad | Überschreitet ein einzelner Treffer die Ablehnungsgrenze? |
|------|------|-----------|------------------|
| **Stark** | Die Form selbst kann nur von einem Angriff stammen | Der erklärte Grad des Detektors | Ja |
| **Schwach** | Das Token *kommt vor* — in normalen Inhalten ist es allgegenwärtig | Immer `Severity::Low` (5 Punkte) | **Nein** |

Beide Stufen stammen vom selben Detektor unter demselben `attack_type`; nur `severity` unterscheidet sich. Schwache Signale werden **weiterhin erkannt** und nicht stillschweigend verworfen: Sie erscheinen in `scan()` und summieren sich in `assess()` weiter auf.

Die unmittelbare Folge für den Aufrufer: **Ein einzelnes schwaches Signal ist kein Grund abzulehnen.** Die Referenz-Pipeline ([`examples/waf.rs:166`](../../../examples/waf.rs)) lehnt bei `risk.level >= RiskLevel::High` ab (40 Punkte), ein einzelnes schwaches Signal ist 5 Punkte wert — es erreicht diesen Zweig nicht. Um den Angriff hinter schwachen Signalen zu sehen, muss man den Wert betrachten, den `assess()` liefert, sobald sich Treffer mehrerer Detektoren stapeln:

```rust
let scanner = Scanner::default();

// Drei schwache Signale aus drei verschiedenen Detektoren — erst der Stapel eskaliert
let a = scanner.assess("<script src=\"/app.js\"></script>\n../config\n__proto__");
// a.results == 3, a.score == 15 (3 × Low) → RiskLevel::Medium
// noch unter High; jeder weitere Treffer in derselben Anfrage überschreitet die Grenze
```

Zu schwachen Signalen herabgestuft werden die Token, bei denen „Vorkommen normal ist":

| Schwaches Signal | Warum es allein nicht ablehnen kann |
|--------|-------------------|
| `<script src=...>`, `<iframe>`, `<link>`, `expression(` | Jede Webseite hat sie |
| Ein einstufiges `../` | Relative Pfade in jeder Quelldatei |
| `-2`, `+1` am Zeilenanfang | Markdown-Listenpunkte, negative Zahlen im Fließtext |
| Ein nacktes `__proto__` (Lesen des Prototyps) | Jedes JS, das die Prototypkette berührt |
| `${env:}` / `${sys:}` | Gültige log4j2-Konfigurationssyntax |
| `X-Forwarded-Host`, `X-Original-URL` | Reverse Proxies setzen sie selbst |
| `Host: 10.244.1.5`, `Host: localhost` | k8s-Pod-zu-Pod-Aufrufe, lokale Entwicklung |
| Nackte `10.0.0.5`, `192.168.1.1`, `127.0.0.1` | `X-Forwarded-For`, `bind 127.0.0.1` |
| `//evil.com`, protokollrelative URL | Quelltextkommentare, CDN-Links in der Doku |
| `information_schema` | PG-Fehlerprotokolle, SQL-Tutorials |

Diese Tabelle ist nur ein Beispiel. Entscheidend ist die **Form**, nicht der Dateiname: Bei demselben `../` ist eine einzelne Ebene (`../x`) schwach und sind mehrere Ebenen (`../../`) stark ([`src/file/path_traversal.rs`](../../../src/file/path_traversal.rs)). Die vollständige Liste steht in den `WEAK_PATTERNS` der einzelnen Detektoren und in den `schwach`-Markierungen der Tabellen unten.

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

Mit `schwach` markierte Muster in den Tabellen sind **schwache Signale**: Sie melden `Severity::Low` (5 Punkte) und überschreiten die Ablehnungsgrenze nicht allein (siehe vorstehenden Abschnitt). Die Spalte „Schweregrad" ist die **Obergrenze** des jeweiligen Detektors; ein Detektor mit `schwach`-Einträgen hat beide Stufen, und seine starken Muster melden weiterhin den erklärten Grad. Ein durchgehend schwacher Detektor (`dns_rebinding`) hat als Obergrenze `Low`.
*(Die Beschriftungen im Diagramm sind auf Chinesisch; die Bezeichner sind API-Namen.)*

### Injection-Angriffe (11 Detektoren)

| Detektor | Abgedeckte Muster | Schweregrad |
|--------|---------|--------|
| **xss** | Event-Handler wie `onerror=`/`onload=` (die vollständige Handler-Tabelle), Pseudo-Protokolle `javascript:`/`vbscript:` (nur wenn dem Schema direkt ein Nicht-Leerzeichen folgt); `schwach`: Tags `<script src=...>`/`<iframe>`/`<embed>`/`<object>`/`<link>`, CSS `expression(` | Critical |
| **sql_injection** | `UNION SELECT`, verzögerte Injection mit `sleep()`/`benchmark()`/`pg_sleep()` (nur in Statement-Position), Stored Procedures `exec sp_`/`xp_`, Boolean-Blind-Injection-Muster `' OR '1'='1`, `LOAD_FILE()`/`INTO OUTFILE`, `DROP TABLE`/`INSERT INTO`, Zerlegung durch Kommentare (`UN/**/ION`); `schwach`: das bloße Wort `information_schema` | Critical |
| **command_injection** | Reverse Shell über `/dev/tcp`, Aufrufformen `passthru()`/`shell_exec()`/`system("…")`/`popen()`/`pcntl_exec()`, Aufrufformen `powershell -Command`/`cmd.exe /c`; `schwach`: Backtick-Spannen, `$()`-Subshells, Verkettung über Pipe/`\|\|`/`&&`, `exec(`, `>/dev/null`, Reader+Pfad wie `cat /etc/passwd`, nackte Wörter `cmd.exe`/`powershell` | Critical |
| **nosql_injection** | MongoDB-Operatoren `$ne`/`$gt`/`$regex`/`$where`, `$or`-Injection, Authentifizierungs-Bypass `{"$gt": ""}` | Critical |
| **ldap_injection** | Filter-Operatoren `(&` `(\|` `(!`, Attribut-Enumeration `*(cn=`, `objectClass`/`uid`-Injection | High |
| **xpath_injection** | Boolean-Bypass `' or '1'='1`, Funktions-Injection `' or true()`, Knoten-Traversierung `'] \| '` | High |
| **jndi_injection** | Der Lookup `${jndi:` selbst, Groß-/Kleinschreibungs-Faltung `${lower:j}`/`${upper:j}`, Faltung über den leeren String `${::-j}` (existiert nur, um `jndi` zu verschleiern); `schwach`: `${env:}`/`${sys:}`/`${java:}` — gültige Lookup-Syntax | Critical |
| **ssi_injection** | Befehlsausführung `<!--#exec cmd=`, Inklusion `<!--#include file=` mit absolutem Pfad oder `..`, Umgebungsausgabe `<!--#printenv`; `schwach`: `<!--#echo var=`, `<!--#fsize`/`<!--#flastmod`, `<!--#config`, übliche Inklusionen wie `<!--#include file="header.html"` | High |
| **graphql_injection** | Introspektion in Query-Form `__schema {`/`__type {` (die bloße Nennung des Feldnamens im Fließtext wird nicht gemeldet); `schwach`: `__typename` (Apollo/Relay hängen es an jede Query), ≥5 Ebenen verschachtelter geschweifter Klammern | Medium |
| **ssti** | Jinja2 `{{ }}` / FreeMarker `${ }` — **Auswertung innerhalb der Delimiter** (`{{7*7}}`, `${7*7}`, `{{config`, `${T(java.lang.Runtime)}`, `${@Type@method}`), Template-LFI über `{% include '/…'` / `..`, Escape-Ketten innerhalb der Delimiter `__mro__`/`__subclasses__()`/`__globals__`/`__builtins__`/`__class__`/`__dict__`, FreeMarker `?new(`; `schwach`: nackte Template-Direktiven `{% %}`/`<%=`/`<%@`/`#set(`, nackte magische Attribute; die Delimiter allein sind kein Signal, ein reiner Platzhalter wie `${x}` wird nicht gemeldet | Critical |
| **format_string** | `%n`-Schreibspezifizierer (auch mit Längenmodifikatoren), überlange Breitenangaben `%123456d`, gehäufte `%x`/`%p`/`%s`-Spezifizierer (Format-String-Leak / Speicherkorruption) | Medium |

### Protokoll- und Request-Angriffe (11 Detektoren)

| Detektor | Abgedeckte Muster | Schweregrad |
|--------|---------|--------|
| **ssrf** | Cloud-Metadaten `169.254.169.254` und `metadata.google.internal` (ohne URL-Kontext), interne IPs in **URL-Authority-Position** (nach `//`) `10.x`/`172.16-31.x`/`192.168.x`/`127.x`, `//localhost`, `//0.0.0.0`, `//[::1]`, gefährliche Protokolle `gopher://`/`dict://`/`ftp://user@`/`file:///`; `schwach`: dieselben internen Literale in **Nicht-URL-Position** (`X-Forwarded-For: 10.0.0.5`, `bind 127.0.0.1`, `{"host": "10.0.0.1"}` sind byteweise identisch) | Critical |
| **xxe** | Entitäts-Deklarationen `<!ENTITY`, externe Referenzen `SYSTEM`/`PUBLIC`, Parameter-Entitäten `%`, DTD-Deklaration `<!DOCTYPE` | Critical |
| **header_injection** | Antwort-spezifische Header nach vorangestelltem `\r\n`: `Set-Cookie`/`Location`/`Refresh`/`Status`/`WWW-Authenticate`, oder `%0d` zusammen mit `%0a` (auch in umgekehrter Reihenfolge `%0a…%0d`). `Content-Length`/`Content-Type`/`Transfer-Encoding` sind **Request**-Header und byteweise identisch mit dem Header jeder wohlgeformten Anfrage; sie sind deshalb kein Signal mehr (die kodierte Form `%0d%0aContent-Length:` wird weiterhin von `%0d`+`%0a` abgedeckt) | High |
| **host_header** | **Zwei** `Host:`-Header (RFC 7230 §5.4 verlangt 400, zwei Parser lesen unterschiedliche Werte); `schwach`: `X-Forwarded-Host`/`X-Original-URL`/`X-Rewrite-URL` — Proxies setzen diese Header selbst, byteweise identisch mit einer Fälschung durch den Client (`X-Forwarded-For`/`X-Forwarded-Proto` werden gar nicht gemeldet) | High |
| **request_smuggling** | Doppelte `Transfer-Encoding`-Header, Smuggling über `Content-Length: 0`, Obfuskation des Chunked-Abschlusses `\r\n0\r\n` | High |
| **open_redirect** | Sprünge über Pseudo-Protokolle `javascript:`/`data:text/html`/`data:text/plain` (Schema mit folgendem Inhalt); `schwach`: protokollrelative URLs `//evil.com` — identisch mit CDN-Links in Quelltextkommentaren und Doku | Medium |
| **cors** | `Access-Control-Allow-Origin: null` sowie `Access-Control-Allow-Origin: *` **zusammen mit** `Access-Control-Allow-Credentials: true`; `schwach`: `Origin: null` auf der Request-Seite (Sandbox-iframes, `data:`-URLs und lokale Dateien haben genau diesen Origin — es braucht ein spiegelndes `ACAO: null`, damit es greift). Einzeln sind beide für öffentliche APIs und statische Assets normal und werden nicht gemeldet | Medium |
| **websocket** | `Origin: null` zusammen mit einem WebSocket-Upgrade (CSWSH), `ws://` auf Loopback-/private/Link-Local-Adressen (inkl. Cloud-Metadaten-Endpunkt `169.254.169.254`) | High |
| **dns_rebinding** | Host-Header mit internen IPs `127.x`/`10.x`/`192.168.x`/`172.16-31.x`, `localhost`, `[::1]`, `0.0.0.0`. **Der Detektor ist durchgehend schwach**: Er meldet immer `Low` — siehe „Bekannte Grenzen" | Low |
| **log4shell** | Lookup-Obfuskation `${lower:j}`/`${upper:j}`, Obfuskation mit leerem String `${::-j}`, verschachtelte Lookups `${${...}:...}`, URL-kodierte Variante `%24%7b...%7d...ndi` | Critical |
| **hpp** | Vermischung der Trennzeichen `&`/`;` (`?a=1&b=2;c=3`), bei der zwei Parser-Ebenen zu unterschiedlichen Parameterzahlen kommen; `schwach`: wiederholte Schlüssel wie `?id=1&id=2` — byteweise identisch mit einem legitimen Mehrfachparameter wie `?tag=rust&tag=web` | Medium |

### Daten- und Serialisierungsangriffe (7 Detektoren)

| Detektor | Abgedeckte Muster | Schweregrad |
|--------|---------|--------|
| **deserialization** | PHP-serialisierte Objekte `O:Zahl:`/`C:Zahl:`, Arrays `a:Zahl:{`, `unserialize()`-Aufrufe, magische Methoden in **Aufrufform** (`__wakeup(`/`__destruct(`/`__construct(`/`__toString(`/`__get(`/`__set(`/`__call(`); `schwach`: nackte Namen magischer Methoden (auch Dokumentation, die sie bespricht, trifft) | Critical |
| **csv_injection** | Ein `=`, das unmittelbar auf ein Trennzeichen `,`/`;`/`\t` folgt und dem ein Nicht-Leerzeichen folgt (Formel in der zweiten Zelle einer TSV-/CSV-Zeile), `DDE` am Zeilenanfang, `cmd\|` am Zeilenanfang, `@SUM(` am Zeilenanfang; `schwach`: `=`/`+`/`-` am Zeilenanfang, gefolgt weder von einem Leerzeichen noch von einem gleichartigen Symbol (`- item` als Listenpunkt, `---` als Trennlinie, `++i`, `= 5` treffen nicht). `@` wurde ganz aus der groben Stufe entfernt (`@media`/`@import` sind in Stylesheets allgegenwärtig); nur `@SUM(` bleibt. Tabulator und Wagenrücklauf sind **Trennzeichen**, kein Formelbeginn | Medium |
| **mail_header** | Zwei benachbarte `From:`-Header, `MIME-Version:` am Zeilenanfang (ein Name, den die HTTP-Feldtabelle nicht kennt); `schwach`: `Cc:`/`Bcc:` am Zeilenanfang — byteweise identisch mit weitergeleiteter Post und eingelesenen Nachrichtentexten. `Content-Type: multipart` und `boundary=` wurden **gestrichen** (`Content-Type: multipart/form-data` ist der Standard-Header jedes Datei-Upload-POST). Die Obergrenze ist Medium (15 Punkte): **allein überschreitet der Detektor die Ablehnungsgrenze nicht** | Medium |
| **jwt_attack** | Bypass mit leerem Algorithmus `alg: none`, Path-Traversal-Injection über `kid`, leeres Signatur-Segment, leeres Payload-Segment | High |
| **prototype_pollution** | `__proto__` als Schlüssel oder Zuweisungsziel (`"__proto__":`, `[__proto__]`, `__proto__ = x`), `constructor.prototype`/`constructor[`, `__defineGetter__`/`__defineSetter__`/`__lookupGetter__`/`__lookupSetter__`, `hasOwnProperty[`; `schwach`: ein nacktes `__proto__` (`obj.__proto__` ist schlicht die Leseform der Sprache) | High |
| **formula_injection** | Formelzeichen am Feldanfang mit Befehls-Pipe `=cmd\|`, gefährliche Tabellenfunktionen `HYPERLINK`/`IMPORTXML`/`IMPORTDATA`/`IMPORTRANGE`/`WEBSERVICE`/`RTD`/`EXEC`, Datenabfluss über `\|` + Zellbezug `A0`, `DDE(`-Aufrufe, `@`-Funktionen | High |
| **redos** | Katastrophales Backtracking: verschachtelte Quantifizierer `(a+)+`/`(a{2,})+`, überlappende Alternativen `(a\|ab)+`, Quantifizierer über `\w`/`\d`/`.`-Gruppen | Medium |

### Dateien und sensible Daten (3 Detektoren)

| Detektor | Abgedeckte Muster | Schweregrad |
|--------|---------|--------|
| **path_traversal** | **Mehrstufiger** Pfadaufstieg `(?:\.\./){2,}`/`(?:\.\.\\){2,}`, URL-kodierter Bypass `%2e%2e`/`..%2f`/`..%5c`, Protokoll-Wrapper `php://filter`/`php://input`/`phar://`/`zip://`/`data://`/`expect://`/`glob://`, Null-Byte-Terminierung `%00`; `schwach`: ein einstufiges `../`/`..\` (identisch mit einem relativen Pfad in Quelltext oder Doku) | Critical |
| **upload** | PHP-Tags `<?php`/`<?=`, ASP-Tags `<%@`/`<%=`, Backdoor-Muster `eval($_`/`system($_`/`exec($_`/`passthru($_`, Superglobals `$_GET`/`$_POST`/`$_REQUEST`/`$_SERVER`, Kodierungs-Bypass mit `base64_decode()` | Critical |
| **data_leak** | 16-stellige Kreditkarten-PAN (Visa/MasterCard/AmEx/Discover/JCB/Diners), AWS Access Keys `AKIA...`, PEM-Private-Key-Header `-----BEGIN`, OpenAI/LLM-API-Keys `sk-...`, Datenbank-Verbindungsstrings `mongodb://`/`mysql://`/`postgresql://`/`redis://` (**müssen `@`-Userinfo tragen**: `mysql://root:secret@db` wird gemeldet, `redis://shared-memory` und `postgres://localhost:5432/app` sind gewöhnliche Konfiguration und werden **nicht** gemeldet), `jdbc:` (ohne diese Einschränkung), JWT-Tokens | Critical |

---

## Bekannte Grenzen

Die folgenden Punkte sind **bekannte, bewusst beibehaltene** Grenzen und keine Mängel, die auf eine Korrektur warten. Vor Änderungen bitte die Begründung lesen — jeder Punkt beruht auf Messungen, und jeder hat bereits einen Versuch abgewehrt, ihn zu verschärfen.

### `dns_rebinding` meldet nur, es blockiert nicht

Sein Kriterium lautet „im `Host:`-Header steht eine interne Adresse" — und genau diese Form hat jeder Pod-zu-Pod-Aufruf in k8s (`Host: 10.244.1.5:8080`), jede lokale Entwicklung (`Host: localhost:8000`) und jede Anfrage im Docker-Containernetz (`172.18.0.2`). Echtes Rebinding ist „öffentlicher Domainname + Auflösungsergebnis zeigt nach innen", und der `Host`, den der Browser sendet, ist genau dieser öffentliche Name — **in einer einzelnen Zeichenkette ist keine Auflösungshistorie zu sehen**, die von diesem Detektor geprüfte Form deckt sich also nicht mit der Angriffsform; keine Verschärfung hilft. Deshalb ist der Detektor durchgehend schwach und meldet immer `Low`; egal wie viele Treffer sich stapeln, allein überschreitet er die Ablehnungsgrenze nie. Der Schutz gehört hinter die Namensauflösung, in den Vergleich der resultierenden IP — nicht in die String-Ebene.

### Diese Bibliothek kann ihren eigenen Quelltext, ihre Tests und ihre Doku nicht scannen

Die Obergrenze des Signatur-Scanners: gemessen an diesem Repository überschreiten 78 von 298 Dateien die Ablehnungsgrenze, und sie enthalten **konstruktionsbedingt** alle Angriffsstrings — Testlasten, die Regex-Literale der Detektor-Quelltexte selbst und die README- und OWASP-Tabellen, die diese Muster auflisten. Ein README wird nicht dadurch mangelhaft, dass es `(a+)+` auflistet. Wer die eigenen Artefakte scannen will, muss diesen Korpus zuerst ausschließen — oder ein anderes Kriterium wählen.

### `upload` meldet `<%@` / `<?php` überall als Critical

Der Vertrag dieses Detektors lautet „**dieser Blob ist serverseitig ausführbarer Code**" — Vorhandensein genügt, deshalb gibt es keine Stufenteilung. Eine JSP-Seite und eine JSP-Webshell teilen ihre Präambel byteweise (`<%@ page language="java" … %>` und `<%@ page import="java.io.*" %>` sind dieselbe Form); `<%@`/`<%=` herabzustufen hieße, Webshells unter die Ablehnungsgrenze fallen zu lassen — Löschen unter anderem Namen. Der Preis: Auch das Scannen einer **gerade ausgelieferten** Seite (statt einer hochgeladenen Datei) trifft; das ist eine falsche Eingabedomäne — die Treffermeldung `Malicious file upload detected` benennt sie.

### `path_traversal` meldet `(?:\.\./){2,}` als Critical

Ein tiefer relativer Pfad in einem Monorepo (`from '../../../shared/domain'`) trifft. Es wird nicht weiter verschärft, weil die einzige Einschränkung, die ihn von einem Angriff trennt, eine Liste von Zieldateinamen ist (`../etc/passwd` und Verwandte) — und die deckt nur Systemdateien ab: Der Angreifer wählt einfach ein anderes LFI-Ziel.

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

// Starkes Signal: Die Form kann nur von einem Angriff stammen ⇒ erklärter Schweregrad
let results = scanner.scan("<img src=x onerror=alert(1)>");
// [CRITICAL] XSS cross-site scripting detected — offset: 11, pattern: onerror=

// Schwaches Signal: das Token kommt nur vor ⇒ immer Low, allein überschreitet es die Grenze nicht
let weak = scanner.scan("<script src=\"/app.js\"></script>");
// [LOW] XSS tag present (weak signal) — offset: 0, pattern: <script>
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

# Tests (580: 431 Unit-Tests, 148 Integrationstests, 1 Dokumentationstest)
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
