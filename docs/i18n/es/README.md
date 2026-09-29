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

### Dos niveles: señales fuertes y débiles

Un detector **no** reporta cada coincidencia con la severidad que declara. 18 de los 32 detectores reparten sus patrones en dos niveles (los estáticos `STRONG_PATTERNS` / `WEAK_PATTERNS` del código fuente):

| Nivel | Criterio | Severidad reportada | ¿Una sola coincidencia cruza la línea de rechazo? |
|------|------|-----------|------------------|
| **Fuerte** | La forma en sí solo puede venir de un ataque | El nivel declarado del detector | Sí |
| **Débil** | El token *aparece* sin más — abunda en el contenido normal | Siempre `Severity::Low` (5 puntos) | **No** |

Ambos niveles salen del mismo detector y del mismo `attack_type`; solo cambia `severity`. Las señales débiles **siguen detectándose** y no se pierden en silencio: aparecen en `scan()` y se siguen acumulando en `assess()`.

La consecuencia para el llamador es directa: **una señal débil aislada no justifica un rechazo.** El canal de referencia ([`examples/waf.rs:166`](../../../examples/waf.rs)) rechaza con `risk.level >= RiskLevel::High` (40 puntos), y una señal débil vale 5 — no llega a esa rama. Para ver el ataque que hay detrás de las señales débiles hay que mirar lo que produce `assess()` cuando se apilan las coincidencias de varios detectores:

```rust
let scanner = Scanner::default();

// Tres señales débiles de tres detectores distintos — solo el apilamiento escala
let a = scanner.assess("<script src=\"/app.js\"></script>\n../config\n__proto__");
// a.results == 3, a.score == 15 (3 × Low) → RiskLevel::Medium
// sigue por debajo de High; cualquier otra coincidencia en la misma petición cruza la línea
```

Se degradan a señal débil los tokens en los que «aparecer es normal»:

| Señal débil | Por qué no puede rechazar por sí sola |
|--------|-------------------|
| `<script src=...>`, `<iframe>`, `<link>`, `expression(` | Los tiene cualquier página web |
| Un `../` de un solo nivel | Rutas relativas de cualquier archivo fuente |
| `-2`, `+1` al inicio de línea | Elementos de lista Markdown, números negativos en prosa |
| Un `__proto__` desnudo (lectura del prototipo) | Cualquier JS que toque la cadena de prototipos |
| `${env:}` / `${sys:}` | Sintaxis válida de configuración de log4j2 |
| `X-Forwarded-Host`, `X-Original-URL` | Los proxies inversos los añaden ellos mismos |
| `Host: 10.244.1.5`, `Host: localhost` | Llamadas pod a pod en k8s, desarrollo local |
| `10.0.0.5`, `192.168.1.1`, `127.0.0.1` desnudos | `X-Forwarded-For`, `bind 127.0.0.1` |
| `//evil.com`, URL relativa al protocolo | Comentarios de código, enlaces CDN de la documentación |
| `information_schema` | Registros de error de PG, tutoriales de SQL |

Esta tabla es solo un ejemplo. El criterio es la **forma**, no el nombre del archivo: para un mismo `../`, un solo nivel (`../x`) es débil y varios niveles (`../../`) son fuertes ([`src/file/path_traversal.rs`](../../../src/file/path_traversal.rs)). La lista completa está en los `WEAK_PATTERNS` de cada detector y en las marcas `débil` de las tablas siguientes.

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

Los patrones marcados como `débil` en las tablas son **señales débiles**: reportan `Severity::Low` (5 puntos) y no cruzan la línea de rechazo por sí solos (véase la sección anterior). La columna «Severidad» es el **techo** del detector; un detector con entradas `débil` tiene ambos niveles, y sus patrones fuertes siguen reportando el nivel declarado. Un detector enteramente débil (`dns_rebinding`) tiene `Low` como techo.
*(Las anotaciones del diagrama están en chino; las etiquetas son nombres de API.)*

### Ataques de inyección (11 detectores)

| Detector | Patrones cubiertos | Severidad |
|--------|---------|--------|
| **xss** | Manejadores de eventos como `onerror=`/`onload=` (la tabla completa de manejadores), protocolos pseudo `javascript:`/`vbscript:` (solo si al esquema le sigue directamente un carácter no blanco); `débil`: etiquetas `<script src=...>`/`<iframe>`/`<embed>`/`<object>`/`<link>`, `expression(` de CSS | Critical |
| **sql_injection** | `UNION SELECT`, inyección de retardos `sleep()`/`benchmark()`/`pg_sleep()` (solo en posición de sentencia), procedimientos almacenados `exec sp_`/`xp_`, patrón de ceguera booleana `' OR '1'='1`, `LOAD_FILE()`/`INTO OUTFILE`, `DROP TABLE`/`INSERT INTO`, corte por comentarios (`UN/**/ION`); `débil`: la sola palabra `information_schema` | Critical |
| **command_injection** | Shell inversa `/dev/tcp`, formas de llamada `passthru()`/`shell_exec()`/`system("…")`/`popen()`/`pcntl_exec()`, formas de llamada `powershell -Command`/`cmd.exe /c`; `débil`: tramos entre comillas invertidas, subcomandos `$()`, encadenado con tubería/`\|\|`/`&&`, `exec(`, `>/dev/null`, lector+ruta del tipo `cat /etc/passwd`, palabras desnudas `cmd.exe`/`powershell` | Critical |
| **nosql_injection** | Operadores de MongoDB `$ne`/`$gt`/`$regex`/`$where`, inyección `$or`, bypass de autenticación `{"$gt": ""}` | Critical |
| **ldap_injection** | Operadores de filtro `(&` `(\|` `(!`, enumeración de atributos `*(cn=`, inyección de `objectClass`/`uid` | High |
| **xpath_injection** | Bypass booleano `' or '1'='1`, inyección de función `' or true()`, recorrido de nodos `'] \| '` | High |
| **jndi_injection** | El propio lookup `${jndi:`, plegado de mayúsculas/minúsculas `${lower:j}`/`${upper:j}`, plegado por cadena vacía `${::-j}` (existe solo para ofuscar `jndi`); `débil`: `${env:}`/`${sys:}`/`${java:}` — sintaxis de lookup válida | Critical |
| **ssi_injection** | Ejecución de comandos `<!--#exec cmd=`, inclusión `<!--#include file=` con ruta absoluta o `..`, volcado de entorno `<!--#printenv`; `débil`: `<!--#echo var=`, `<!--#fsize`/`<!--#flastmod`, `<!--#config`, inclusiones rutinarias como `<!--#include file="header.html"` | High |
| **graphql_injection** | Introspección en forma de consulta `__schema {`/`__type {` (la mera mención del nombre del campo en prosa no se reporta); `débil`: `__typename` (Apollo/Relay lo añaden a cada consulta), ≥5 niveles de llaves anidadas | Medium |
| **ssti** | Jinja2 `{{ }}` / FreeMarker `${ }` — **evaluación dentro de los delimitadores** (`{{7*7}}`, `${7*7}`, `{{config`, `${T(java.lang.Runtime)}`, `${@Type@method}`), LFI de plantilla vía `{% include '/…'` / `..`, cadenas de escape dentro de los delimitadores `__mro__`/`__subclasses__()`/`__globals__`/`__builtins__`/`__class__`/`__dict__`, FreeMarker `?new(`; `débil`: directivas de plantilla desnudas `{% %}`/`<%=`/`<%@`/`#set(`, atributos mágicos desnudos; los delimitadores por sí solos no son señal, un simple marcador como `${x}` no se reporta | Critical |
| **format_string** | especificadores de escritura `%n` (también con modificadores de longitud), anchos desmesurados `%123456d`, especificadores `%x`/`%p`/`%s` repetidos (fuga de cadena de formato / corrupción de memoria) | Medium |

### Ataques de protocolo y peticiones (11 detectores)

| Detector | Patrones cubiertos | Severidad |
|--------|---------|--------|
| **ssrf** | Metadatos de nube `169.254.169.254` y `metadata.google.internal` (sin contexto de URL), IPs internas en **posición de autoridad de URL** (tras `//`) `10.x`/`172.16-31.x`/`192.168.x`/`127.x`, `//localhost`, `//0.0.0.0`, `//[::1]`, protocolos peligrosos `gopher://`/`dict://`/`ftp://user@`/`file:///`; `débil`: los mismos literales internos en **posición que no es URL** (`X-Forwarded-For: 10.0.0.5`, `bind 127.0.0.1`, `{"host": "10.0.0.1"}` son idénticos byte a byte) | Critical |
| **xxe** | Declaraciones de entidades `<!ENTITY`, referencias externas `SYSTEM`/`PUBLIC`, entidades de parámetro `%`, declaración DTD `<!DOCTYPE` | Critical |
| **header_injection** | Cabeceras propias de la respuesta precedidas de `\r\n`: `Set-Cookie`/`Location`/`Refresh`/`Status`/`WWW-Authenticate`, o `%0d` junto con `%0a` (también en orden inverso `%0a…%0d`). `Content-Length`/`Content-Type`/`Transfer-Encoding` son cabeceras de **petición**, idénticas byte a byte a las de cualquier petición bien formada, así que ya no son señal (la forma codificada `%0d%0aContent-Length:` sigue cubierta por `%0d`+`%0a`) | High |
| **host_header** | **Dos** cabeceras `Host:` (la RFC 7230 §5.4 exige un 400, dos analizadores leen valores distintos); `débil`: `X-Forwarded-Host`/`X-Original-URL`/`X-Rewrite-URL` — los proxies añaden esas cabeceras ellos mismos, idénticas byte a byte a una falsificación del cliente (`X-Forwarded-For`/`X-Forwarded-Proto` no se reportan en absoluto) | High |
| **request_smuggling** | Cabeceras `Transfer-Encoding` duplicadas, contrabando `Content-Length: 0`, ofuscación de terminación chunked `\r\n0\r\n` | High |
| **open_redirect** | Saltos por protocolos pseudo `javascript:`/`data:text/html`/`data:text/plain` (esquema seguido de contenido); `débil`: URLs relativas al protocolo `//evil.com` — idénticas a los enlaces CDN de comentarios de código y documentación | Medium |
| **cors** | `Access-Control-Allow-Origin: null` y `Access-Control-Allow-Origin: *` **junto con** `Access-Control-Allow-Credentials: true`; `débil`: `Origin: null` en la petición (los iframes en sandbox, las URLs `data:` y los archivos locales tienen exactamente ese origen — hace falta que un `ACAO: null` lo devuelva para que cuaje). Por separado ambos son normales en APIs públicas y recursos estáticos y no se reportan | Medium |
| **websocket** | `Origin: null` junto con una actualización WebSocket (CSWSH), `ws://` hacia direcciones de loopback/privadas/link-local (incluido el endpoint de metadatos cloud `169.254.169.254`) | High |
| **dns_rebinding** | Host header con IPs internas `127.x`/`10.x`/`192.168.x`/`172.16-31.x`, `localhost`, `[::1]`, `0.0.0.0`. **El detector es enteramente débil**: siempre reporta `Low` — véase «Límites conocidos» | Low |
| **log4shell** | ofuscación de lookup `${lower:j}`/`${upper:j}`, ofuscación con cadena vacía `${::-j}`, lookups anidados `${${...}:...}`, variante codificada en URL `%24%7b...%7d...ndi` | Critical |
| **hpp** | Mezcla de los separadores `&`/`;` (`?a=1&b=2;c=3`), en la que dos capas de analizadores obtienen números de parámetros distintos; `débil`: claves repetidas como `?id=1&id=2` — idénticas byte a byte a un parámetro multivalor legítimo como `?tag=rust&tag=web` | Medium |

### Ataques de datos y serialización (7 detectores)

| Detector | Patrones cubiertos | Severidad |
|--------|---------|--------|
| **deserialization** | Objetos serializados PHP `O:número:`/`C:número:`, arrays `a:número:{`, llamadas `unserialize()`, métodos mágicos en **forma de llamada** (`__wakeup(`/`__destruct(`/`__construct(`/`__toString(`/`__get(`/`__set(`/`__call(`); `débil`: nombres de métodos mágicos desnudos (la documentación que los comenta también se detecta) | Critical |
| **csv_injection** | Un `=` inmediatamente después de un separador `,`/`;`/`\t` y seguido de un carácter no blanco (fórmula en la segunda celda de una fila TSV/CSV), `DDE` al inicio de línea, `cmd\|` al inicio de línea, `@SUM(` al inicio de línea; `débil`: `=`/`+`/`-` al inicio de línea seguidos ni de un blanco ni de un símbolo de la misma familia (`- item` como elemento de lista, `---` como línea divisoria, `++i`, `= 5` no coinciden). `@` se retiró por completo del nivel grueso (`@media`/`@import` abundan en las hojas de estilo); solo queda `@SUM(`. El tabulador y el retorno de carro son **separadores**, no inicios de fórmula | Medium |
| **mail_header** | Dos cabeceras `From:` contiguas, `MIME-Version:` al inicio de línea (un nombre ausente de la tabla de campos HTTP); `débil`: `Cc:`/`Bcc:` al inicio de línea — idénticas byte a byte a un correo reenviado o a un cuerpo de mensaje ingerido. `Content-Type: multipart` y `boundary=` se **eliminaron** (`Content-Type: multipart/form-data` es la cabecera estándar de todo POST de subida de archivos). El techo es Medium (15 puntos): **el detector no cruza la línea de rechazo por sí solo** | Medium |
| **jwt_attack** | Bypass con algoritmo vacío `alg: none`, inyección de path traversal en `kid`, segmento de firma vacío, segmento de payload vacío | High |
| **prototype_pollution** | `__proto__` como clave u objetivo de asignación (`"__proto__":`, `[__proto__]`, `__proto__ = x`), `constructor.prototype`/`constructor[`, `__defineGetter__`/`__defineSetter__`/`__lookupGetter__`/`__lookupSetter__`, `hasOwnProperty[`; `débil`: un `__proto__` desnudo (`obj.__proto__` es simplemente cómo el lenguaje lee un prototipo) | High |
| **formula_injection** | caracteres de fórmula al inicio del campo con tubería de comando `=cmd\|`, funciones de hoja de cálculo peligrosas `HYPERLINK`/`IMPORTXML`/`IMPORTDATA`/`IMPORTRANGE`/`WEBSERVICE`/`RTD`/`EXEC`, exfiltración vía `\|` + referencia de celda `A0`, llamadas `DDE(`, funciones `@` | High |
| **redos** | retroceso catastrófico: cuantificadores anidados `(a+)+`/`(a{2,})+`, alternativas solapadas `(a\|ab)+`, cuantificador sobre un grupo `\w`/`\d`/`.` | Medium |

### Archivos y datos sensibles (3 detectores)

| Detector | Patrones cubiertos | Severidad |
|--------|---------|--------|
| **path_traversal** | Escape **multinivel** `(?:\.\./){2,}`/`(?:\.\.\\){2,}`, bypass por codificación URL `%2e%2e`/`..%2f`/`..%5c`, wrappers de protocolo `php://filter`/`php://input`/`phar://`/`zip://`/`data://`/`expect://`/`glob://`, truncamiento con byte nulo `%00`; `débil`: un `../`/`..\` de un solo nivel (idéntico a una ruta relativa en código o documentación) | Critical |
| **upload** | Etiquetas PHP `<?php`/`<?=`, etiquetas ASP `<%@`/`<%=`, patrones de backdoor `eval($_`/`system($_`/`exec($_`/`passthru($_`, superglobales `$_GET`/`$_POST`/`$_REQUEST`/`$_SERVER`, bypass por `base64_decode()` | Critical |
| **data_leak** | PAN de tarjetas de crédito de 16 dígitos (Visa/MasterCard/AmEx/Discover/JCB/Diners), AWS Access Key `AKIA...`, cabecera de claves privadas PEM `-----BEGIN`, API Keys OpenAI/LLM `sk-...`, cadenas de conexión a bases de datos `mongodb://`/`mysql://`/`postgresql://`/`redis://` (**deben llevar userinfo `@`**: `mysql://root:secret@db` se reporta; `redis://shared-memory` y `postgres://localhost:5432/app` son configuración ordinaria y **no** se reportan), `jdbc:` (sin esa restricción), tokens JWT | Critical |

---

## Límites conocidos

Los siguientes puntos son límites **conocidos y deliberadamente mantenidos**, no defectos pendientes de arreglo. Antes de tocarlos, lee la justificación: cada uno se apoya en mediciones, y cada uno ya ha frenado un intento de endurecerlo.

### `dns_rebinding` solo reporta, no bloquea

Su criterio es «en la cabecera `Host:` aparece una dirección interna» — y esa misma forma es la de toda llamada pod a pod en k8s (`Host: 10.244.1.5:8080`), la de todo desarrollo local (`Host: localhost:8000`) y la de toda petición en la red de contenedores de Docker (`172.18.0.2`). El rebinding real es «un dominio público + un resultado de resolución que apunta hacia dentro», y el `Host` que envía el navegador es precisamente ese nombre público: **una sola cadena no contiene historial de resolución**, así que la forma que prueba este detector no se solapa con la forma del ataque y no hay dirección en la que endurecerlo. Por eso el detector es enteramente débil y siempre reporta `Low`; por muchas coincidencias que se apilen, nunca cruza la línea de rechazo por sí solo. La protección va después de la resolución, comparando la IP resultante, no en la capa de cadenas.

### Esta librería no puede escanear su propio código fuente, sus pruebas ni su documentación

El techo del escáner de firmas: medido sobre este repositorio, 78 de 298 archivos cruzan la línea de rechazo, y todos ellos contienen cadenas de ataque **por construcción**: cargas de prueba, los propios literales de expresión regular del código de los detectores y las tablas de README/OWASP que nombran esos patrones. Un README no es defectuoso por listar `(a+)+`. Escanear tus propios artefactos exige excluir antes ese corpus, o elegir otro criterio.

### `upload` reporta `<%@` / `<?php` como Critical allí donde aparezcan

El contrato de este detector es «**este blob es código ejecutable en el servidor**»: la mera presencia lo establece, así que no hay reparto en niveles. Una página JSP y un webshell JSP comparten su preámbulo byte a byte (`<%@ page language="java" … %>` y `<%@ page import="java.io.*" %>` son la misma forma); degradar `<%@`/`<%=` dejaría los webshells por debajo de la línea de rechazo, es decir, borrar con otro nombre. El precio: escanear una página **que se está sirviendo** (y no un archivo subido) también coincide; eso es un dominio de entrada inadecuado — el mensaje de coincidencia `Malicious file upload detected` lo nombra.

### `path_traversal` reporta `(?:\.\./){2,}` como Critical

Una ruta relativa profunda en un monorepo (`from '../../../shared/domain'`) coincide. No se endurece más porque la única restricción que la separa de un ataque es una lista de nombres de archivo objetivo (`../etc/passwd` y compañía), y esa solo cubre archivos del sistema: el atacante simplemente elige otro objetivo de LFI.

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

// Señal fuerte: la forma solo puede venir de un ataque ⇒ la severidad declarada
let results = scanner.scan("<img src=x onerror=alert(1)>");
// [CRITICAL] XSS cross-site scripting detected — offset: 11, pattern: onerror=

// Señal débil: el token solo aparece ⇒ siempre Low, no cruza la línea de rechazo por sí sola
let weak = scanner.scan("<script src=\"/app.js\"></script>");
// [LOW] XSS tag present (weak signal) — offset: 0, pattern: <script>
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

# Pruebas (580: 431 unitarias, 148 de integración, 1 de documentación)
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
