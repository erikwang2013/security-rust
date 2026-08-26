<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust

**🌐 [中文 (原文)](../../README.md)**

Librería de detección de ataques escrita en Rust, que cubre 27 detectores en 4 grandes categorías: ataques de inyección, ataques de protocolo, ataques de datos/serialización y fuga de archivos/datos sensibles. Cero dependencias de frameworks externos, escaneo puro de cadenas.

---

## Filosofía de diseño

### Por qué «detección» en lugar de «bloqueo»

Esta librería se posiciona como un **escáner de entrada puro**: recibe una cadena y devuelve resultados de detección estructurados. No está vinculada a ningún framework web, no analiza peticiones/respuestas HTTP ni implementa bloqueo en tiempo real. De esta forma puedes integrarla en cualquier cadena: motores de reglas WAF, auditoría de logs, validación previa en puertas de enlace de API, herramientas CLI de escaneo de seguridad, etc.

### Principios de arquitectura

- **Responsabilidad única** — cada detector se ocupa de un solo tipo de ataque y mantiene internamente un conjunto compilado de patrones de expresiones regulares
- **Interfaz unificada** — el trait `Detector` es el único contrato de todos los detectores: `fn detect(&self, input: &str) -> Option<DetectionResult>`
- **Cobertura por defecto** — `Scanner::default()` ensambla los 27 detectores de una sola vez, utilizable con cero configuración
- **Configuración opcional** — `Scanner::builder()` permite personalizar a demanda, ensamblando selectivamente detectores con `.with_detector()`

### Compromisos

| Decisión | Elección | Razón |
|------|------|------|
| Expresiones regulares vs parser | Expresiones regulares | En escenarios de detección la velocidad es prioritaria; las expresiones regulares ofrecen mejor cobertura de patrones ofuscados/evasivos |
| Primero que llega vs detección completa | Detección completa | Una entrada puede disparar varios tipos de ataque a la vez; no deben producirse falsos negativos |
| Cero dependencias vs introducir serde | Cero dependencias | Solo depende de `regex` + `thiserror`; compilación rápida, tamaño reducido |

---

## Arquitectura de diseño

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

### Responsabilidades de los módulos

| Módulo | Ruta | N.º de detectores | Responsabilidad |
|------|------|---------|------|
| Núcleo | `src/lib.rs` `result.rs` `scanner.rs` | — | Trait `Detector`, `DetectionResult`, `Scanner`/`ScannerBuilder` |
| Inyección | `src/injection/` | 10 | XSS, inyección SQL, inyección de comandos, NoSQL, LDAP, XPATH, JNDI, SSI, GraphQL, SSTI |
| Protocolo | `src/protocol/` | 9 | SSRF, XXE, inyección de cabeceras, ataque de Host header, contrabando de peticiones, redirección abierta, CORS, WebSocket, DNS rebinding |
| Datos | `src/data/` | 5 | Deserialización PHP, inyección de fórmulas CSV, inyección de cabeceras de correo, ataques JWT, contaminación de prototipos |
| Archivos | `src/file/` | 3 | Path traversal, subida de archivos maliciosos, fuga de datos sensibles |

### Estructura del resultado de detección

`DetectionResult` devuelve de forma estructurada seis campos: `attack_type`, `category`, `severity`, `matched_pattern`, `offset`, `message`. La definición completa está en la [referencia de la API](./API.md).

---

## Funcionalidades implementadas

### Ataques de inyección (10 detectores)

| Detector | Patrones cubiertos | Severidad |
|--------|---------|--------|
| **xss** | `<script>`, manejadores de eventos como `onerror=`, protocolo pseudo `javascript:`, etiquetas `<svg>`/`<iframe>`, `expression()` de CSS, `eval()`, `document.cookie` | Critical |
| **sql_injection** | `UNION SELECT`, inyección de retardos `sleep()`/`benchmark()`/`pg_sleep()`, enumeración `information_schema`, procedimientos almacenados `exec sp_`/`xp_`, patrón de ceguera booleana `' OR '1'='1`, `LOAD_FILE()`/`INTO OUTFILE` | Critical |
| **command_injection** | Comandos entre comillas invertidas, subcomandos `$()`, ejecución encadenada con tuberías, shell inversa `/dev/tcp`, funciones PHP `passthru()`/`shell_exec()`/`system()`, invocación de `cmd.exe`/`powershell` | Critical |
| **nosql_injection** | Operadores de MongoDB `$ne`/`$gt`/`$regex`/`$where`, inyección `$or`, bypass de autenticación `{"$gt": ""}` | Critical |
| **ldap_injection** | Operadores de filtro `(&` `(|` `(!`, enumeración de atributos `*(cn=`, inyección de `objectClass`/`uid` | High |
| **xpath_injection** | Bypass booleano `' or '1'='1`, inyección de función `' or true()`, recorrido de nodos `'] | '` | High |
| **jndi_injection** | `${jndi:ldap://`, ofuscación `${lower:j}`, ofuscación `${upper:j}`, ofuscación de cadena vacía `${::-j}`, búsqueda de variables de entorno `${env:}`, propiedades de sistema `${sys:}` | Critical |
| **ssi_injection** | Ejecución de comandos `<!--#exec cmd=`, inclusión de archivos `<!--#include file=`, salida de variables `<!--#echo var=`, información de archivos `<!--#fsize`/`<!--#flastmod` | High |
| **graphql_injection** | Consultas de introspección `__schema`/`__type`, DoS por anidamiento profundo (≥5 niveles) | Medium |
| **ssti** | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<%=` `<%@`, Velocity `#set()`, escape de sandbox Python MRO `__mro__`/`__subclasses__()` | Critical |

### Ataques de protocolo y peticiones (9 detectores)

| Detector | Patrones cubiertos | Severidad |
|--------|---------|--------|
| **ssrf** | Metadatos de nube `169.254.169.254`, IPs internas RFC1918 (10.x, 172.16-31.x, 192.168.x), loopback `127.x`, loopback IPv6 `::1`, `0.0.0.0`, protocolos peligrosos `gopher://`/`dict://`/`ftp://`/`file://` | Critical |
| **xxe** | Declaraciones de entidades `<!ENTITY`, referencias externas `SYSTEM`/`PUBLIC`, entidades de parámetro `%`, declaración DTD `<!DOCTYPE` | Critical |
| **header_injection** | CRLF codificado en URL `%0d%0a`, inyección CRLF cruda `\r\n` | High |
| **host_header** | Inyección de múltiples Host headers, envenenamiento `X-Forwarded-Host`/`X-Original-URL`/`X-Rewrite-URL`, Host con CRLF | High |
| **request_smuggling** | Cabeceras `Transfer-Encoding` duplicadas, contrabando `Content-Length: 0`, ofuscación de terminación chunked `\r\n0\r\n` | High |
| **open_redirect** | URL relativa a protocolo `//evil.com`, saltos por pseudo protocolos `javascript:`/`data:text/html` | Medium |
| **cors** | Bypass `Origin: null`, combinación `Access-Control-Allow-Origin: *` + Credentials | Medium |
| **websocket** | Handshake `Upgrade: websocket`, WS entre dominios `Origin: null`, conexiones en claro `ws://` | High |
| **dns_rebinding** | Host header con IPs internas `127.x`/`10.x`/`192.168.x`/`172.16-31.x`, `localhost`, `::1`, `0.0.0.0` | High |

### Ataques de datos y serialización (5 detectores)

| Detector | Patrones cubiertos | Severidad |
|--------|---------|--------|
| **deserialization** | Objetos serializados PHP `O:número:`/`C:número:`, arrays `a:número:{`, llamadas `unserialize()`, métodos mágicos `__wakeup`/`__destruct`/`__toString` | Critical |
| **csv_injection** | Caracteres de fórmula `=`/`+`/`-`/`@` al inicio de línea, DDE (intercambio dinámico de datos), tubería de comandos `cmd|`, función `@SUM()` | Medium |
| **mail_header** | Inyección en copia oculta `Bcc:`/`Cc:`, múltiples remitentes `From:`, inyección de cabeceras MIME `MIME-Version:`/`Content-Type: multipart`, manipulación de límite `boundary=` | Medium |
| **jwt_attack** | Bypass con algoritmo vacío `alg: none`, inyección de path traversal en `kid`, segmento de firma vacío, segmento de payload vacío | High |
| **prototype_pollution** | Contaminación de la cadena de prototipos `__proto__`/`constructor.prototype`, secuestro de propiedades `__defineGetter__`/`__defineSetter__`/`__lookupGetter__`/`__lookupSetter__` | High |

### Archivos y datos sensibles (3 detectores)

| Detector | Patrones cubiertos | Severidad |
|--------|---------|--------|
| **path_traversal** | Escape de directorios `../`/`..\\`, bypass por codificación URL `%2e%2e`, wrappers de protocolo `php://filter`/`php://input`/`phar://`/`zip://`/`data://`/`expect://`/`glob://`, truncamiento con byte nulo `%00` | Critical |
| **upload** | Etiquetas PHP `<?php`/`<?=`, etiquetas ASP `<%@`/`<%=`, patrones de backdoor `eval($_`/`system($_`/`exec($_`/`passthru($_`, superglobales `$_GET`/`$_POST`/`$_REQUEST`/`$_SERVER`, bypass por `base64_decode()` | Critical |
| **data_leak** | PAN de tarjetas de crédito de 16 dígitos (Visa/MasterCard/AmEx/Discover/JCB/Diners), AWS Access Key `AKIA...`, cabecera de claves privadas PEM `-----BEGIN`, API Keys OpenAI/LLM `sk-...`, cadenas de conexión a bases de datos `mongodb://`/`mysql://`/`postgresql://`/`redis://`/`jdbc:`, tokens JWT | Critical |

---

## Guía de uso

Utilizable con cero configuración:

```rust
use security_rust::Scanner;

let scanner = Scanner::default();
let results = scanner.scan("<script>alert('xss')</script>");
// [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
```

La referencia completa de la API (instalación, escaneo selectivo, configuración personalizada, visualización de severidad, rendimiento) está en la [referencia de la API](./API.md).

---

## Desarrollo

```bash
# Compilar
cargo build --release

# Pruebas (46 pruebas de integración)
cargo test

# Revisión de código
cargo clippy -- -D warnings
```

---

## Donaciones / Patrocinio

Si este proyecto te ha resultado útil, eres bienvenido a apoyarlo con una donación (voluntaria).

| Alipay | WeChat Pay |
|--------|---------|
| ![Alipay](./alipay.png) | ![WeChat Pay](./weixinpay.png) |

### Transferencia global (transferencia internacional)

【Información del beneficiario】
- Nombre del beneficiario: WANG KEXUN
- Número de cuenta del beneficiario: 881015918251

【Banco beneficiario】
- SWIFT Code de ZA Bank: AABLHKHHXXX
- Nombre del banco: ZA Bank Limited
- Número de banco: 387
- Dirección del banco: Core F, Cyberport 3, 100 Cyberport Road, Hong Kong

【Banco agente para remesas transfronterizas (si es necesario)】

Tenga en cuenta que esta es la información del banco agente (banco intermediario) para remesas transfronterizas, no la del banco beneficiario. Consulte con su banco si necesita proporcionar la información del banco agente para remesas transfronterizas.

El banco agente para remesas en dólares de Hong Kong, renminbi y dólares estadounidenses es Citibank:
- Nombre del banco: Citibank N.A. Hong Kong
- SWIFT Code: CITIHKHXXXX
- Número de banco: 006
- Nombre de la sucursal: Hong Kong Branch
- Número de sucursal: 391
- Dirección del banco: Citibank Tower, Citibank Plaza, 3 Garden Road, Central, Hong Kong

El banco agente para remesas en otras divisas es BNY Mellon:
- Nombre del banco: THE BANK OF NEW YORK MELLON
- SWIFT Code: IRVTUS3NXXX
- Dirección del banco: THE BANK OF NEW YORK MELLON, 240 GREENWICH STREET, NEW YORK, United States

---

## Licencia

MIT — Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
