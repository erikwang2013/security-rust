<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust

**🌐 [中文 (原文)](../../README.md)**

In Rust geschriebene Angriffserkennungsbibliothek, die 27 Detektoren in vier Kategorien abdeckt: Injection-Angriffe, Protokollangriffe, Daten-/Serialisierungsangriffe sowie Datei-/Datenlecks. Keine externen Framework-Abhängigkeiten, reine String-Scans.

---

## Designphilosophie

### Warum „Erkennung" statt „Blockierung"

Diese Bibliothek ist als **reiner Eingabescanner** konzipiert — sie empfängt Strings und liefert strukturierte Erkennungsergebnisse. Sie ist an kein Web-Framework gebunden, führt keine HTTP-Request-/Response-Analyse durch und implementiert keine Echtzeit-Blockierung. Dadurch lässt sie sich in jede Kette einbetten: WAF-Regel-Engines, Log-Audits, vorgelagerte Validierung in API-Gateways, CLI-Sicherheits-Scan-Tools usw.

### Architekturprinzipien

- **Einzelverantwortung** — jeder Detektor kümmert sich um genau eine Angriffsart und hält intern kompilierte Regelsätze aus regulären Ausdrücken
- **Einheitliche Schnittstelle** — das `Detector`-Trait ist der einzige Vertrag aller Detektoren: `fn detect(&self, input: &str) -> Option<DetectionResult>`
- **Standardabdeckung** — `Scanner::default()` montiert mit einem Klick alle 27 Detektoren, einsatzbereit ohne Konfiguration
- **Optionale Konfiguration** — `Scanner::builder()` unterstützt bedarfsgerechte Anpassung; mit `.with_detector()` lassen sich Detektoren selektiv montieren

### Abwägungen

| Entscheidung | Wahl | Begründung |
|------|------|------|
| Regex vs. Parser | Regex | Geschwindigkeit hat im Erkennungsszenario Vorrang; Regex deckt verzerrte/Bypass-Muster besser ab |
| Ersttreffer vs. vollständige Erkennung | Vollständige Erkennung | Eine Eingabe kann mehrere Angriffsarten gleichzeitig auslösen; nichts darf übersehen werden |
| Null-Abhängigkeiten vs. Einführung von serde | Null-Abhängigkeiten | Nur `regex` + `thiserror`; schnelle Kompilierung, kleine Größe |

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

### Zuständigkeiten der Module

| Modul | Pfad | Anzahl Detektoren | Zuständigkeit |
|------|------|---------|------|
| Kern | `src/lib.rs` `result.rs` `scanner.rs` | — | `Detector`-Trait, `DetectionResult`, `Scanner`/`ScannerBuilder` |
| Injection | `src/injection/` | 10 | XSS, SQL-Injection, Command-Injection, NoSQL, LDAP, XPATH, JNDI, SSI, GraphQL, SSTI |
| Protokoll | `src/protocol/` | 9 | SSRF, XXE, Header-Injection, Host-Header-Angriffe, Request Smuggling, Open Redirect, CORS, WebSocket, DNS-Rebinding |
| Daten | `src/data/` | 5 | PHP-Deserialisierung, CSV-Formel-Injection, E-Mail-Header-Injection, JWT-Angriffe, Prototype Pollution |
| Datei | `src/file/` | 3 | Path Traversal, bösartige Datei-Uploads, Leck sensibler Daten |

### Struktur des Erkennungsergebnisses

`DetectionResult` liefert strukturiert sechs Felder: `attack_type`, `category`, `severity`, `matched_pattern`, `offset`, `message`. Die vollständige Definition findest du in der [API-Referenz](./API.md).

---

## Implementierte Funktionen

### Injection-Angriffe (10 Detektoren)

| Detektor | Abgedeckte Muster | Schweregrad |
|--------|---------|--------|
| **xss** | `<script>`, Event-Handler wie `onerror=`, `javascript:`-Pseudo-Protokoll, `<svg>`/`<iframe>`-Tags, CSS `expression()`, `eval()`, `document.cookie` | Critical |
| **sql_injection** | `UNION SELECT`, verzögerte Injection mit `sleep()`/`benchmark()`/`pg_sleep()`, Enumeration von `information_schema`, Stored Procedures `exec sp_`/`xp_`, Boolean-Blind-Injection-Muster `' OR '1'='1`, `LOAD_FILE()`/`INTO OUTFILE` | Critical |
| **command_injection** | Backtick-Befehle, `$()`-Subshells, Verkettung über Pipe-Symbole, Reverse Shell über `/dev/tcp`, PHP-Funktionen `passthru()`/`shell_exec()`/`system()`, Aufrufe von `cmd.exe`/`powershell` | Critical |
| **nosql_injection** | MongoDB-Operatoren `$ne`/`$gt`/`$regex`/`$where`, `$or`-Injection, Authentifizierungs-Bypass `{"$gt": ""}` | Critical |
| **ldap_injection** | Filter-Operatoren `(&` `(|` `(!`, Attribut-Enumeration `*(cn=`, `objectClass`/`uid`-Injection | High |
| **xpath_injection** | Boolean-Bypass `' or '1'='1`, Funktions-Injection `' or true()`, Knoten-Traversierung `'] | '` | High |
| **jndi_injection** | `${jndi:ldap://`, Obfuskation `${lower:j}`, Obfuskation `${upper:j}`, Obfuskation mit leerem String `${::-j}`, Umgebungsvariablen-Nachschlag `${env:}`, Systemeigenschaften `${sys:}` | Critical |
| **ssi_injection** | Befehlsausführung `<!--#exec cmd=`, Datei-Inklusion `<!--#include file=`, Variablen-Ausgabe `<!--#echo var=`, Datei-Informationen `<!--#fsize`/`<!--#flastmod` | High |
| **graphql_injection** | Introspection-Abfragen `__schema`/`__type`, tief verschachteltes DoS (≥5 Ebenen) | Medium |
| **ssti** | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<%=` `<%@`, Velocity `#set()`, Python-MRO-Sandbox-Escape `__mro__`/`__subclasses__()` | Critical |

### Protokoll- und Request-Angriffe (9 Detektoren)

| Detektor | Abgedeckte Muster | Schweregrad |
|--------|---------|--------|
| **ssrf** | Cloud-Metadaten `169.254.169.254`, RFC1918-interne IPs (10.x, 172.16-31.x, 192.168.x), `127.x`-Loopback, `::1`-IPv6-Loopback, `0.0.0.0`, gefährliche Protokolle `gopher://`/`dict://`/`ftp://`/`file://` | Critical |
| **xxe** | Entitäts-Deklarationen `<!ENTITY`, externe Referenzen `SYSTEM`/`PUBLIC`, Parameter-Entitäten `%`, DTD-Deklaration `<!DOCTYPE` | Critical |
| **header_injection** | URL-kodiertes CRLF `%0d%0a`, rohe CRLF-Injection `\r\n` | High |
| **host_header** | Mehrfache Host-Header-Injection, Vergiftung über `X-Forwarded-Host`/`X-Original-URL`/`X-Rewrite-URL`, CRLF im Host-Header | High |
| **request_smuggling** | Doppelte `Transfer-Encoding`-Header, Smuggling über `Content-Length: 0`, Obfuskation des Chunked-Abschlusses `\r\n0\r\n` | High |
| **open_redirect** | Protokoll-relative URLs `//evil.com`, Sprünge über Pseudo-Protokolle `javascript:`/`data:text/html` | Medium |
| **cors** | `Origin: null`-Bypass, Kombination `Access-Control-Allow-Origin: *` + Credentials | Medium |
| **websocket** | Handshake `Upgrade: websocket`, Cross-Origin-WebSocket `Origin: null`, unverschlüsselte `ws://`-Verbindungen | High |
| **dns_rebinding** | Host-Header mit internen IPs `127.x`/`10.x`/`192.168.x`/`172.16-31.x`, `localhost`, `::1`, `0.0.0.0` | High |

### Daten- und Serialisierungsangriffe (5 Detektoren)

| Detektor | Abgedeckte Muster | Schweregrad |
|--------|---------|--------|
| **deserialization** | PHP-serialisierte Objekte `O:Zahl:`/`C:Zahl:`, Arrays `a:Zahl:{`, `unserialize()`-Aufrufe, magische Methoden wie `__wakeup`/`__destruct`/`__toString` | Critical |
| **csv_injection** | Formelzeichen `=`/`+`/`-`/`@` am Zeilenanfang, DDE (Dynamic Data Exchange), Befehls-Pipes `cmd|`, `@SUM()`-Funktion | Medium |
| **mail_header** | Blindkopie-Injection `Bcc:`/`Cc:`, mehrfache Absender `From:`, MIME-Header-Injection `MIME-Version:`/`Content-Type: multipart`, Manipulation der `boundary=`-Grenze | Medium |
| **jwt_attack** | Bypass mit leerem Algorithmus `alg: none`, Path-Traversal-Injection über `kid`, leeres Signatur-Segment, leeres Payload-Segment | High |
| **prototype_pollution** | Prototype-Chain-Pollution `__proto__`/`constructor.prototype`, Property-Kapern über `__defineGetter__`/`__defineSetter__`/`__lookupGetter__`/`__lookupSetter__` | High |

### Dateien und sensible Daten (3 Detektoren)

| Detektor | Abgedeckte Muster | Schweregrad |
|--------|---------|--------|
| **path_traversal** | Directory Traversal `../`/`..\\`, URL-kodierter Bypass `%2e%2e`, Protokoll-Wrapper `php://filter`/`php://input`/`phar://`/`zip://`/`data://`/`expect://`/`glob://`, Null-Byte-Terminierung `%00` | Critical |
| **upload** | PHP-Tags `<?php`/`<?=`, ASP-Tags `<%@`/`<%=`, Backdoor-Muster `eval($_`/`system($_`/`exec($_`/`passthru($_`, Superglobals `$_GET`/`$_POST`/`$_REQUEST`/`$_SERVER`, Kodierungs-Bypass mit `base64_decode()` | Critical |
| **data_leak** | 16-stellige Kreditkarten-PAN (Visa/MasterCard/AmEx/Discover/JCB/Diners), AWS Access Keys `AKIA...`, PEM-Private-Key-Header `-----BEGIN`, OpenAI/LLM-API-Keys `sk-...`, Datenbank-Verbindungsstrings `mongodb://`/`mysql://`/`postgresql://`/`redis://`/`jdbc:`, JWT-Tokens | Critical |

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
# 构建
cargo build --release

# 测试（46 个集成测试）
cargo test

# 代码检查
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
