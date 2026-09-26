<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust

**🌐 [中文 (原文)](../../../README.md)**

Librería de detección de ataques escrita en Rust, que cubre 32 detectores en 4 grandes categorías: ataques de inyección, ataques de protocolo, ataques de datos/serialización y fuga de archivos/datos sensibles. Cero dependencias de frameworks externos: la cadena de detectores trabaja solo con cadenas y se complementa con tres módulos con estado (ver más abajo).

La mascota del proyecto, **甲哨 Sentri** ([`pet.svg`](../../pet.svg)) — 32 placas de caparazón para 32 detectores. Lo reporta todo, no bloquea nada.

---

## Mascota del proyecto: 甲哨 Sentri

<img src="../../pet.svg" alt="甲哨 Sentri — la mascota del proyecto security-rust" width="340">

Un cangrejo centinela con lupa y cartel. El personaje no es decoración: es el diseño de esta librería, dibujado:

| Rasgo | Correspondencia en el diseño |
|------|---------|
| 4 filas × 8 placas de caparazón | 32 detectores sin estado; las 4 filas = inyección / protocolo / datos / archivos |
| Lupa en la pinza izquierda | **Ver** — `Detector::detect()` solo escanea; una coincidencia devuelve una prueba |
| Cartel en la pinza derecha (`已上报` — «reportado») | **Reportar** — devuelve `DetectionResult`, no lanza excepciones ni interrumpe la cadena de llamadas |
| Pinzas que nunca pellizcan | La decisión es del llamador; la única excepción es `SessionGuard`, que sí devuelve `Block` |
| Monóculo | La enfermedad profesional del auditor: cada conclusión lleva `matched_pattern` y `offset`, hasta la posición en el texto original |
| `deps: regex ×1` en la placa | La promesa de cero dependencias: `[dependencies]` solo contiene `regex`, siempre |

Lema: **reportar todo, no bloquear nada.**

La figura va integrada en la librería con `include_str!` (sin coste en tiempo de ejecución: no se enlaza si no se usa), y la versión ASCII puede escribirse directamente en una terminal o un log:

```rust
println!("{}", security_rust::pet::ASCII);
```

---

## Estructura del proyecto

```
security-rust/
├── src/
│   ├── lib.rs              Trait Detector (el único contrato), auxiliar regex_detect, doc del crate
│   ├── scanner.rs          Scanner / ScannerBuilder: ensambla por defecto los 32 detectores
│   ├── result.rs           DetectionResult / AttackCategory / Severity
│   ├── score.rs            Evaluación de riesgo: suma ponderada + tramos → RiskAssessment
│   ├── pet.rs              La mascota del proyecto (NAME / TAGLINE / ASCII / SVG)
│   ├── injection/          11 detectores de inyección
│   ├── protocol/           11 detectores de protocolo
│   ├── data/               7 detectores de datos
│   ├── file/               3 detectores de archivos
│   ├── session/            SessionGuard + SessionStore (guard / store / geo)
│   └── throttle/           Throttle + ThrottleStore (guard / store)
├── tests/                  7 suites de integración: sesión, limitación, ciclo de vida, invariantes, robustez, extremo a extremo, limitación multiclave
├── examples/
│   ├── waf.rs              Ejemplo de canal de extremo a extremo (escaneo → limitación → sesión → acción)
│   └── axum_middleware.rs  Referencia de integración del middleware de axum
├── docs/
│   ├── API.md              Referencia completa de la API
│   ├── OWASP-COVERAGE.md   Matriz de cobertura frente a las clases de ataque de OWASP
│   ├── pet.svg             La mascota del proyecto
│   ├── diagrams/           Diagramas de arquitectura / funcionalidades / ciclo de vida (SVG)
│   ├── i18n/               READMEs y documentos de API en 12 idiomas
│   └── ...                 Códigos QR de donación, informes de revisión y de pruebas
└── Cargo.toml              La única dependencia en tiempo de ejecución: regex
```

---

## Filosofía de diseño

### Por qué «detección» en lugar de «bloqueo»

Esta librería se posiciona como un **escáner de entrada puro**: recibe una cadena y devuelve resultados de detección estructurados. No está vinculada a ningún framework web, no analiza peticiones/respuestas HTTP ni implementa bloqueo en tiempo real. De esta forma puedes integrarla en cualquier cadena: motores de reglas WAF, auditoría de logs, validación previa en puertas de enlace de API, herramientas CLI de escaneo de seguridad, etc. Los módulos `session`, `throttle` y `score` (ver más abajo) van más allá: mantienen estado o agregan señales, y siguen sin depender de ningún framework.

### Principios de arquitectura

- **Responsabilidad única** — cada detector se ocupa de un solo tipo de ataque y mantiene internamente un conjunto compilado de patrones de expresiones regulares
- **Interfaz unificada** — el trait `Detector` es el único contrato de todos los detectores: `fn detect(&self, input: &str) -> Option<DetectionResult>`
- **Cobertura por defecto** — `Scanner::default()` ensambla los 32 detectores de una sola vez, utilizable con cero configuración
- **Configuración opcional** — `Scanner::builder()` permite personalizar a demanda, ensamblando selectivamente detectores con `.with_detector()`

### Compromisos

| Decisión | Elección | Razón |
|------|------|------|
| Expresiones regulares vs parser | Expresiones regulares | En escenarios de detección la velocidad es prioritaria; las expresiones regulares ofrecen mejor cobertura de patrones ofuscados/evasivos |
| Primero que llega vs detección completa | Detección completa | Una entrada puede disparar varios tipos de ataque a la vez; no deben producirse falsos negativos |
| Cero dependencias vs introducir serde | Cero dependencias | Solo depende de `regex`; compilación rápida, tamaño reducido |
| Detector vs módulo con estado | Separados | `Detector::detect(&str)` solo recibe una cadena y no puede expresar la entrada compuesta «token + huella + posición + tiempo»; por eso `session` / `throttle` van junto al `Scanner`, no dentro de él |
| fail-closed vs fail-open | Autenticación fail-closed, limitación de tasa fail-open | Una decisión de sesión que deja pasar equivale a un bypass y debe bloquear; la limitación de tasa dejaría fuera a todos los usuarios (auto-DoS), y la barrera principal de autenticación sigue bloqueando — la decisión es del llamador |

---

## Arquitectura de diseño

<img src="../../diagrams/architecture.svg" alt="security-rust arquitectura: llamador → capa de detección → capa de evaluación → capa de guarda → abstracción de almacenamiento" width="900">

Cinco capas, de arriba abajo: **llamador** (WAF / puerta de enlace / auditoría / CLI) → **capa de detección** (`Scanner` con `Vec<Box<dyn Detector>>`, 32 detectores en 4 categorías) → **capa de evaluación** (`score::assess`) → **capa de guarda** (`SessionGuard` / `Throttle`, cada uno ligado a un trait de almacenamiento) → **abstracción de almacenamiento** (`MemoryStore` integrado, Redis implementado por el llamador).
*(Las anotaciones del diagrama están en chino; las etiquetas son nombres de API.)*

El trait `Detector` es el único contrato de la capa de detección: `fn detect(&self, input: &str) -> Option<DetectionResult>`. `session`, `throttle` y `score` no lo implementan — su entrada no es una sola cadena (token + huella + posición y tiempo), o bien consumen los resultados del escaneo en lugar de la entrada bruta — así que responden por su cuenta (ver más abajo). El camino de retorno rojo, a la derecha, marca el límite de esta librería: **el veredicto vuelve al llamador para que lo ejecute**; la librería nunca toca la petición.

### Responsabilidades de los módulos

| Módulo | Ruta | N.º de detectores | Responsabilidad |
|------|------|---------|------|
| Núcleo | `src/lib.rs` `result.rs` `scanner.rs` | — | Trait `Detector`, `DetectionResult`, `Scanner`/`ScannerBuilder` |
| Inyección | `src/injection/` | 11 | XSS, inyección SQL, inyección de comandos, NoSQL, LDAP, XPATH, JNDI, SSI, GraphQL, SSTI, cadena de formato |
| Protocolo | `src/protocol/` | 11 | SSRF, XXE, inyección de cabeceras, ataque de Host header, contrabando de peticiones, redirección abierta, CORS, WebSocket, DNS rebinding, Log4Shell, contaminación de parámetros HTTP |
| Datos | `src/data/` | 7 | Deserialización PHP, inyección de fórmulas CSV, inyección de cabeceras de correo, ataques JWT, contaminación de prototipos, inyección de fórmulas, ReDoS |
| Archivos | `src/file/` | 3 | Path traversal, subida de archivos maliciosos, fuga de datos sensibles |

### Estructura del resultado de detección

`DetectionResult` devuelve de forma estructurada seis campos: `attack_type`, `category`, `severity`, `matched_pattern`, `offset`, `message`. La definición completa está en la [referencia de la API](./API.md).

---

## Funcionalidades implementadas

<img src="../../diagrams/features.svg" alt="security-rust funcionalidades: inyección 11, protocolo 11, datos 7, archivos 3, más tres módulos con estado" width="900">

Los 32 detectores se ensamblan por categoría y se activan todos sin configuración mediante `Scanner::default()`. Las tablas siguientes detallan lo que cubre cada uno y su severidad. La severidad describe una sola coincidencia; el riesgo global agregado es el que devuelve `Scanner::assess()`.
*(Las anotaciones del diagrama están en chino; las etiquetas son nombres de API.)*

### Ataques de inyección (11 detectores)

| Detector | Patrones cubiertos | Severidad |
|--------|---------|--------|
| **xss** | `<script>`, manejadores de eventos como `onerror=`, protocolo pseudo `javascript:`, etiquetas `<svg>`/`<iframe>`, `expression()` de CSS, `eval()`, `document.cookie` | Critical |
| **sql_injection** | `UNION SELECT`, inyección de retardos `sleep()`/`benchmark()`/`pg_sleep()`, enumeración `information_schema`, procedimientos almacenados `exec sp_`/`xp_`, patrón de ceguera booleana `' OR '1'='1`, `LOAD_FILE()`/`INTO OUTFILE` | Critical |
| **command_injection** | Comandos entre comillas invertidas, subcomandos `$()`, ejecución encadenada con tuberías, shell inversa `/dev/tcp`, funciones PHP `passthru()`/`shell_exec()`/`system()`, invocación de `cmd.exe`/`powershell` | Critical |
| **nosql_injection** | Operadores de MongoDB `$ne`/`$gt`/`$regex`/`$where`, inyección `$or`, bypass de autenticación `{"$gt": ""}` | Critical |
| **ldap_injection** | Operadores de filtro `(&` `(\|` `(!`, enumeración de atributos `*(cn=`, inyección de `objectClass`/`uid` | High |
| **xpath_injection** | Bypass booleano `' or '1'='1`, inyección de función `' or true()`, recorrido de nodos `'] \| '` | High |
| **jndi_injection** | `${jndi:ldap://`, ofuscación `${lower:j}`, ofuscación `${upper:j}`, ofuscación de cadena vacía `${::-j}`, búsqueda de variables de entorno `${env:}`, propiedades de sistema `${sys:}` | Critical |
| **ssi_injection** | Ejecución de comandos `<!--#exec cmd=`, inclusión de archivos `<!--#include file=`, salida de variables `<!--#echo var=`, información de archivos `<!--#fsize`/`<!--#flastmod` | High |
| **graphql_injection** | Consultas de introspección `__schema`/`__type`, DoS por anidamiento profundo (≥5 niveles) | Medium |
| **ssti** | Jinja2 `{{ }}` / FreeMarker `${ }` — **evaluación dentro de los delimitadores** (`{{7*7}}`, `${7*7}`, `{{config`, `${T(java.lang.Runtime)}`), ERB `<%=` `<%@`, Velocity `#set()`, cadenas de escape de Python `__mro__`/`__subclasses__()`/`__globals__`/`__builtins__`/`__class__`/`__dict__`; los delimitadores por sí solos no son señal, un simple marcador como `${x}` no se reporta | Critical |
| **format_string** | especificadores de escritura `%n` (también con modificadores de longitud), anchos desmesurados `%123456d`, especificadores `%x`/`%p`/`%s` repetidos (fuga de cadena de formato / corrupción de memoria) | Medium |

### Ataques de protocolo y peticiones (11 detectores)

| Detector | Patrones cubiertos | Severidad |
|--------|---------|--------|
| **ssrf** | Metadatos de nube `169.254.169.254`, IPs internas RFC1918 (10.x, 172.16-31.x, 192.168.x), loopback `127.x`, loopback IPv6 `::1`, `0.0.0.0`, protocolos peligrosos `gopher://`/`dict://`/`ftp://`/`file://` | Critical |
| **xxe** | Declaraciones de entidades `<!ENTITY`, referencias externas `SYSTEM`/`PUBLIC`, entidades de parámetro `%`, declaración DTD `<!DOCTYPE` | Critical |
| **header_injection** | CRLF codificado en URL `%0d%0a`, inyección CRLF cruda `\r\n` | High |
| **host_header** | Inyección de múltiples Host headers, envenenamiento `X-Forwarded-Host`/`X-Original-URL`/`X-Rewrite-URL`, Host con CRLF | High |
| **request_smuggling** | Cabeceras `Transfer-Encoding` duplicadas, contrabando `Content-Length: 0`, ofuscación de terminación chunked `\r\n0\r\n` | High |
| **open_redirect** | URL relativa a protocolo `//evil.com`, saltos por pseudo protocolos `javascript:`/`data:text/html` | Medium |
| **cors** | `Access-Control-Allow-Origin: null`, `Origin: null` (el indicador canónico de iframes en sandbox y CSWSH) y `Access-Control-Allow-Origin: *` **junto con** `Access-Control-Allow-Credentials: true`. Por separado ambos son normales en APIs públicas y recursos estáticos y no se reportan | Medium |
| **websocket** | `Origin: null` junto con una actualización WebSocket (CSWSH), `ws://` hacia direcciones de loopback/privadas/link-local (incluido el endpoint de metadatos cloud `169.254.169.254`) | High |
| **dns_rebinding** | Host header con IPs internas `127.x`/`10.x`/`192.168.x`/`172.16-31.x`, `localhost`, `::1`, `0.0.0.0` | High |
| **log4shell** | ofuscación de lookup `${lower:j}`/`${upper:j}`, ofuscación con cadena vacía `${::-j}`, lookups anidados `${${...}:...}`, variante codificada en URL `%24%7b...%7d...ndi` | Critical |
| **hpp** | mezcla de separadores en la cadena de consulta `&a=1;b=2` y `;a=1&b=2` (contaminación de parámetros por divergencia entre analizadores) | Medium |

### Ataques de datos y serialización (7 detectores)

| Detector | Patrones cubiertos | Severidad |
|--------|---------|--------|
| **deserialization** | Objetos serializados PHP `O:número:`/`C:número:`, arrays `a:número:{`, llamadas `unserialize()`, métodos mágicos `__wakeup`/`__destruct`/`__toString` | Critical |
| **csv_injection** | Caracteres de fórmula al inicio de la celda `=`/`+`/`-`/`@` (el tabulador y el retorno de carro son **separadores**, no inicios de fórmula), un `=` inmediatamente después de un separador `,`/`;`/`\t`, DDE (intercambio dinámico de datos), tubería de comandos `cmd\|`, función `@SUM()` | Medium |
| **mail_header** | Inyección en copia oculta `Bcc:`/`Cc:`, múltiples remitentes `From:`, inyección de cabeceras MIME `MIME-Version:`/`Content-Type: multipart`, manipulación de límite `boundary=` | Medium |
| **jwt_attack** | Bypass con algoritmo vacío `alg: none`, inyección de path traversal en `kid`, segmento de firma vacío, segmento de payload vacío | High |
| **prototype_pollution** | Contaminación de la cadena de prototipos `__proto__`/`constructor.prototype`, secuestro de propiedades `__defineGetter__`/`__defineSetter__`/`__lookupGetter__`/`__lookupSetter__` | High |
| **formula_injection** | caracteres de fórmula al inicio del campo con tubería de comando `=cmd\|`, funciones de hoja de cálculo peligrosas `HYPERLINK`/`IMPORTXML`/`IMPORTDATA`/`IMPORTRANGE`/`WEBSERVICE`/`RTD`/`EXEC`, exfiltración vía `\|` + referencia de celda `A0`, llamadas `DDE(`, funciones `@` | High |
| **redos** | retroceso catastrófico: cuantificadores anidados `(a+)+`/`(a{2,})+`, alternativas solapadas `(a\|ab)+`, cuantificador sobre un grupo `\w`/`\d`/`.` | Medium |

### Archivos y datos sensibles (3 detectores)

| Detector | Patrones cubiertos | Severidad |
|--------|---------|--------|
| **path_traversal** | Escape de directorios `../`/`..\\`, bypass por codificación URL `%2e%2e`, wrappers de protocolo `php://filter`/`php://input`/`phar://`/`zip://`/`data://`/`expect://`/`glob://`, truncamiento con byte nulo `%00` | Critical |
| **upload** | Etiquetas PHP `<?php`/`<?=`, etiquetas ASP `<%@`/`<%=`, patrones de backdoor `eval($_`/`system($_`/`exec($_`/`passthru($_`, superglobales `$_GET`/`$_POST`/`$_REQUEST`/`$_SERVER`, bypass por `base64_decode()` | Critical |
| **data_leak** | PAN de tarjetas de crédito de 16 dígitos (Visa/MasterCard/AmEx/Discover/JCB/Diners), AWS Access Key `AKIA...`, cabecera de claves privadas PEM `-----BEGIN`, API Keys OpenAI/LLM `sk-...`, cadenas de conexión a bases de datos `mongodb://`/`mysql://`/`postgresql://`/`redis://`/`jdbc:`, tokens JWT | Critical |

---

## Módulos con estado

`session`, `throttle` y `score` **no** son implementaciones de `Detector`. `session` y `throttle` tienen estado y están ligados a una identidad: `Detector::detect(&self, input: &str)` no puede expresar una entrada compuesta de token, huella, posición y tiempo. Por eso se sitúan junto a la cadena de detectores, no dentro de ella.

| Módulo | Tipo | Responsabilidad |
|------|------|------|
| `session` | `SessionGuard<S: SessionStore>` | Seguridad de sesión: secuestro de cliente, manipulación de datos, inicio de sesión desde una ubicación inusual, sesiones con token. Métodos `bind`/`verify`/`revoke`/`revoke_all`/`rotate`; `Decision { Allow, Challenge, Block }` + `SessionThreat`; `SessionConfig` (`ttl_secs` 3600, `impossible_travel_kmh` 900.0, `timestamp_skew_secs` 300); trait `SessionStore` + `MemoryStore` |
| `throttle` | `Throttle<S: ThrottleStore>` | Limitación de tasa y bloqueo: ventana deslizante, bloqueo por umbral, bloqueo de cuenta. Métodos `check`/`check_any`/`record_failure`/`record_success`/`reset`/`purge_expired`; `ThrottleDecision { Allow { remaining }, Banned { until }, Unavailable }`; `ThrottleConfig` (`threshold` 5, `window_secs` 60, `ban_secs` 900); `record_failure` devuelve `ThrottleOutcome` (`Allow`/`Banned`), sin `Unavailable` |
| `score` | `RiskLevel`, `RiskAssessment`, `Scanner::assess()` | Evaluación de riesgo: agrega señales sueltas de baja gravedad en una magnitud medible. `RiskLevel { None, Low, Medium, High, Critical }` |

**La asimetría ante fallos es deliberada.** `SessionGuard` devuelve `Decision::Block` (`StoreUnavailable`) si el almacenamiento falla: fail-closed, nunca deja pasar. `Throttle` es la excepción consciente: la limitación de tasa es defensa en profundidad y no una barrera de autenticación principal, así que un fallo del backend devuelve `ThrottleDecision::Unavailable` y no `Banned` — bloquear a todos los usuarios sería un auto-DoS. La decisión queda en manos del llamador.

**Sigue sin haber dependencias nuevas:** la lista se limita a `regex`. El precio: el token y la firma los aporta el llamador, y las posiciones las procesa el llamador. Ambos módulos abstraen su almacenamiento tras un trait; para despliegues con varias instancias basta con implementar `SessionStore`/`ThrottleStore` sobre Redis.

---

## Ciclo de vida

<img src="../../diagrams/lifecycle.svg" alt="security-rust tres ciclos de vida: escaneo, sesión, limitación de tasa" width="900">

Tres ciclos de vida independientes entre sí, que solo confluyen en el manejador de peticiones del llamador:
*(Las anotaciones del diagrama están en chino; las etiquetas son nombres de API.)*

| Ciclo de vida | Inicio | Fin | Dónde vive el estado |
|---------|------|------|---------|
| **Escaneo** | `Scanner::scan(&str)` | `Vec<DetectionResult>` → `score::assess` → `RiskAssessment` | Ninguno: sin estado, cada llamada es independiente |
| **Sesión** | `SessionGuard::bind()` escribe un `SessionRecord` | `verify()` en cada petición → `SessionVerdict` ⇒ `Allow` / `Challenge` / `Block` | `SessionStore` (`MemoryStore` integrado) |
| **Limitación de tasa** | `Throttle::check_any(&[keys])` | `Allow{remaining}` / `Banned{until}` / `Unavailable` | `ThrottleStore` (`MemoryThrottleStore` integrado) |

Dos bordes fáciles de equivocar:

- **`remaining == 0` significa que esta petición debe rechazarse** — la cuota está agotada, no es «un intento más». No lo inviertas al escribir las cabeceras `X-RateLimit-*`.
- **Los fallos de almacenamiento se tratan en direcciones opuestas**: `SessionGuard` es fail-closed (`StoreUnavailable` ⇒ `Block`, nunca deja pasar; si no, un atacante que provoca un fallo del backend neutraliza toda una clase de comprobaciones); `Throttle` es fail-open (`Unavailable` se entrega al llamador, porque dejar fuera a todos los usuarios ante un hipo del backend sería un auto-DoS, y la barrera principal `SessionGuard` sigue bloqueando). Es una decisión de diseño escrita, no un fallback olvidado.

---

## Guía de uso

Utilizable con cero configuración:

```rust
use security_rust::Scanner;

let scanner = Scanner::default();
let results = scanner.scan("<script>alert('xss')</script>");
// [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
```

La evaluación de riesgo convierte la lista de coincidencias en un único nivel, para que las señales de baja gravedad acumuladas no pasen inadvertidas:

```rust
let assessment = scanner.assess("=cmd|' /C calc'!A0 `cat /etc/passwd` ../../../etc/passwd");
// assessment.level   >= RiskLevel::High
// assessment.results >= 3
// assessment.score   — puntos brutos ponderados
```

La referencia completa de la API (instalación, escaneo selectivo, configuración personalizada, evaluación de riesgo, visualización de severidad, seguridad de sesión, limitación de tasa y bloqueo, rendimiento) está en la [referencia de la API](./API.md).

### Seguridad de sesión (`session`)

```rust
use security_rust::session::{Decision, MemoryStore, RequestContext, SessionConfig, SessionGuard};

let guard = SessionGuard::new(MemoryStore::new(), SessionConfig::default());

let login = RequestContext {
    token: "tok-abc",
    subject: "u-1",
    fingerprint: "ip=1.2.3.4|ua=curl",   // huella del cliente, se liga al iniciar sesión
    location: Some("CN-BJ"),
    coords: Some((39.9042, 116.4074)),
    signature: None,                      // el MAC lo firma el llamador
    at: None,
};

// Inicio de sesión: crear la sesión + ligar la huella + registrar la ubicación; una ubicación
// inusual solo afecta al veredicto, no bloquea el inicio de sesión
guard.bind(&login, 1_700_000_000).unwrap();

// Verificación en cada petición: el mismo token con otra huella ⇒ secuestro de cliente
let verdict = guard.verify(&RequestContext { fingerprint: "ip=5.6.7.8|ua=curl", ..login }, 1_700_000_010);

match verdict.decision {
    Decision::Allow => { /* dejar pasar */ }
    Decision::Challenge => { /* dejar pasar pero exigir una segunda verificación: ubicación inusual, desviación de reloj, firma inesperada */ }
    Decision::Block => { /* rechazar */ }
}
```

### Limitación de tasa y bloqueo (`throttle`)

```rust
use security_rust::throttle::{MemoryThrottleStore, Throttle, ThrottleConfig, ThrottleDecision};

let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());
let key = "acct:u-1"; // la clave la construye y normaliza el llamador; no pases la entrada bruta como clave
let now = 1_700_000_000;

// Una petición real tiene dos dimensiones: IP y cuenta. check_any las consulta en una sola llamada
// y las fusiona por estrictez
match throttle.check_any(&["ip:1.2.3.4", key], now) {
    // remaining puede escribirse en X-RateLimit-*; **remaining == 0 significa que esta petición debe rechazarse**
    ThrottleDecision::Allow { remaining } => { /* cupo restante remaining */ }
    // desde now >= until el bloqueo se considera levantado
    ThrottleDecision::Banned { until } => { /* bloqueado, se levanta en until */ }
    // fallo del backend: este módulo no decide por el llamador (recomendado: dejar pasar + alertar)
    ThrottleDecision::Unavailable => { /* backend de limitación no disponible */ }
}

// Registrar un fallo de autenticación: al llegar a threshold se bloquea. Devuelve ThrottleOutcome
// (dos estados); un fallo del almacén va como Err — no hace falta código muerto para una
// rama Unavailable que nunca se ejecuta
let _ = throttle.record_failure(key, now);
```

---

## Desarrollo

```bash
# Compilar
cargo build --release

# Pruebas (494: 365 unitarias, 128 de integración, 1 de documentación)
cargo test

# Ejemplo de canal de extremo a extremo (escaneo → limitación → sesión → acción)
cargo run --example waf

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
