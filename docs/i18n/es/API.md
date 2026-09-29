<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# Referencia de la API de security-rust

[中文](../../../README.md) | [English](../en/API.md) | [한국어](../ko/API.md) | [Русский](../ru/API.md) | [Deutsch](../de/API.md) | [Français](../fr/API.md) | [Português](../pt/API.md) | [हिन्दी](../hi/API.md) | [العربية](../ar/API.md) | [বাংলা](../bn/API.md) | [Bahasa Indonesia](../id/API.md) | [日本語](../ja/API.md) | [Español (本页)](./API.md)

---

## Trait principal

### `Detector`

El único contrato de todos los detectores:

```rust
pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
    fn detect(&self, input: &str) -> Option<DetectionResult>;
}
```

- `name()` — nombre del detector (p. ej. `"xss"`, `"sql_injection"`)
- `detect()` — escanea la entrada; si hay coincidencia devuelve `Some(DetectionResult)`, si no hay coincidencia devuelve `None`

## Estructura del resultado de detección

```rust
pub struct DetectionResult {
    pub attack_type: String,      // "xss", "sql_injection" ...
    pub category: AttackCategory, // Injection | Protocol | Data | File
    pub severity: Severity,       // Critical | High | Medium | Low
    pub matched_pattern: String,  // fragmento del patrón concreto que coincidió
    pub offset: usize,            // desplazamiento de bytes en la entrada
    pub message: String,          // descripción legible por humanos
}
```

## Dos niveles: señales fuertes y débiles

18 de los 32 detectores reparten sus patrones en dos niveles (los estáticos `STRONG_PATTERNS` / `WEAK_PATTERNS` del código fuente). La estructura de campos de `DetectionResult` no cambia; lo que cambia es el valor de `severity`:

| Nivel | Criterio | `severity` | ¿Una sola coincidencia cruza la línea de rechazo? |
|------|------|-----------|------------------|
| **Fuerte** | La forma en sí solo puede venir de un ataque | El nivel declarado del detector | Sí |
| **Débil** | El token *aparece* sin más — abunda en el contenido normal | Siempre `Severity::Low` (5 puntos) | **No** |

Mismo detector, mismo `attack_type`, solo cambia `severity`; `detect()` prueba primero el nivel fuerte y recurre al débil, así que **cada detector devuelve como mucho un resultado**. Las señales débiles se siguen detectando y no se pierden en silencio.

`DetectionResult` no distingue los niveles: para saber si una coincidencia es fuerte o débil basta con comprobar `severity == Severity::Low` (el nivel débil es la única fuente que reporta `Low`). El canal de referencia rechaza a los 40 puntos (`risk.level >= RiskLevel::High`, véase [`examples/waf.rs:166`](../../../examples/waf.rs)); una señal débil aislada vale 5 y no llega a esa rama.

Para ver el ataque que hay detrás de las señales débiles está `assess()`, que apila las coincidencias de varios detectores:

```rust
let scanner = Scanner::default();

// Tres señales débiles de tres detectores distintos — solo el apilamiento llega a Medium (15 puntos), aún por debajo de High
let a = scanner.assess("<script src=\"/app.js\"></script>\n../config\n__proto__");
assert_eq!(a.results, 3);
assert_eq!(a.score, 15);
assert_eq!(a.level, RiskLevel::Medium);
```

Ejemplos de formas degradadas (la lista completa está en los `WEAK_PATTERNS` de cada detector): `<script src=...>`, un `../` de un solo nivel, `-2` al inicio de línea, un `__proto__` desnudo, `${env:}`, `X-Forwarded-Host`, `Host: localhost`, un `10.0.0.5` desnudo, `//evil.com`, `information_schema`.

El criterio es la **forma**, no el nombre del archivo: para un mismo `../`, un solo nivel (`../x`) reporta `Low` y varios niveles (`../../`) reportan `Critical` ([`src/file/path_traversal.rs`](../../../src/file/path_traversal.rs)). Hasta dónde llega cada detector está en las tablas de abajo y en las tablas de funcionalidades del [README](./README.md).

## Scanner

### Instalación

```toml
[dependencies]
security-rust = "2.1.1"
```

### Inicio rápido

```rust
use security_rust::Scanner;

fn main() {
    // Cero configuración: ensambla los 32 detectores
    let scanner = Scanner::default();

    // Escanea la entrada y devuelve todos los ataques detectados (como mucho un resultado por detector)
    let results = scanner.scan("<img src=x onerror=alert(1)>");

    for r in &results {
        println!("[{}] {} — offset: {}, pattern: {}",
            r.severity, r.message, r.offset, r.matched_pattern);
    }
    // Salida:
    // [CRITICAL] XSS cross-site scripting detected — offset: 11, pattern: onerror=

    // Una señal débil usa el mismo detector y el mismo attack_type, pero reporta Low
    let weak = scanner.scan("<script src=\"/app.js\"></script>");
    // [LOW] XSS tag present (weak signal) — offset: 0, pattern: <script>
}
```

### Escaneo selectivo

```rust
let scanner = Scanner::default();

// Ejecuta solo los detectores especificados
let results = scanner.scan_with(
    "1 UNION SELECT password FROM users",
    &["sql_injection", "xss"],
);
```

### Configuración personalizada

```rust
use security_rust::injection::{XssDetector, SqlInjectionDetector};

// Ensambla solo los detectores necesarios mediante el builder
let scanner = Scanner::builder()
    .with_detector(Box::new(XssDetector))
    .with_detector(Box::new(SqlInjectionDetector))
    .build();
```

### Visualización de la severidad

```rust
use security_rust::Severity;

let r = &results[0];
println!("{}", r.severity);  // CRITICAL | HIGH | MEDIUM | LOW
```

Las demás etiquetas de estado también implementan `Display` y se imprimen en mayúsculas: `Decision` (`ALLOW` / `CHALLENGE` / `BLOCK`), `SessionThreat` (p. ej. `impossible travel (11205 km/h)`), `AttackCategory` (en minúsculas, p. ej. `injection`), `ThrottleDecision` (`ALLOW` / `BANNED` / `UNAVAILABLE`) y `ThrottleOutcome` (`ALLOW` / `BANNED`).

```rust
println!("{} {}", verdict.decision, verdict.threats.len());  // BLOCK 2
```

## Módulos con estado

`session` y `throttle` **no** implementan el trait `Detector` de forma deliberada: tienen estado y están ligados a una identidad, y `Detector::detect(&self, input: &str)` no puede expresar una entrada compuesta de token, huella, posición y tiempo. `score` es un cálculo puro sobre `DetectionResult`.

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

// Protección de sesión — fail-closed: Decision::Block si falla el almacenamiento
let sessions = SessionGuard::new(MemoryStore::new(), SessionConfig::default());
let verdict: SessionVerdict = sessions.verify(&ctx, now);
if verdict.decision == Decision::Block {
    // rechazar
}

// Limitación de tasa — defensa en profundidad: Unavailable si falla, no Banned
let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());
match throttle.check("acct:user-42", now) {
    ThrottleDecision::Allow { remaining: 0 } => { /* rechazar: cupo agotado */ }
    ThrottleDecision::Allow { .. } => { /* dejar pasar */ }
    ThrottleDecision::Banned { until } => { /* bloqueado hasta `until` */ }
    ThrottleDecision::Unavailable => { /* decidir por cuenta propia */ }
}

// Fusionar varias dimensiones (p. ej. IP + cuenta): gana el resultado más estricto
let merged = throttle.check_any(&["ip:203.0.113.7", "acct:user-42"], now);
match throttle.record_failure("acct:user-42", now) {
    Ok(outcome) => { /* ThrottleOutcome: Allow { remaining } | Banned { until } */ }
    Err(_) => { /* fallo del almacén */ }
}

// Evaluación de riesgo: agregar señales sueltas en una magnitud medible
let risk = Scanner::default().assess("<script>alert('xss')</script>");
```

| Elemento | Firma / campo |
|------|------|
| `SessionGuard::bind` | `fn bind(&self, ctx: &RequestContext, now: u64) -> Result<SessionVerdict, SessionError>` |
| `SessionGuard::verify` | `fn verify(&self, ctx: &RequestContext, now: u64) -> SessionVerdict` |
| `SessionGuard::revoke` / `revoke_all` | `fn revoke(&self, token: &str) -> Result<(), StoreError>` / `fn revoke_all(&self, subject: &str) -> Result<usize, StoreError>` |
| `SessionGuard::rotate` | renueva el token de una sesión |
| `SessionGuard::purge_expired` | borra las sesiones caducadas y el historial de inicio de sesión de los sujetos inactivos. **El valor de retorno solo cuenta sesiones**, no el historial recuperado |
| `RequestContext` | `token`, `subject`, `fingerprint`, `location`, `coords`, `signature`, `at` |
| `SessionVerdict` | `decision: Decision`, `severity: Option<Severity>` (`None` si se permite), `threats: Vec<SessionThreat>` |
| `Decision` | `Allow` \| `Challenge` \| `Block` |
| `SessionConfig` | `ttl_secs` 3600, `impossible_travel_kmh` 900.0, `timestamp_skew_secs` 300 |
| `SessionStore` | trait del almacenamiento de sesiones; `MemoryStore` es la implementación en memoria incluida |
| `Throttle::check` | `fn check(&self, key: &str, now: u64) -> ThrottleDecision` |
| `Throttle::check_any` | `fn check_any(&self, keys: &[&str], now: u64) -> ThrottleDecision` — fusiona varias dimensiones: `Banned` gana (con el `until` más tardío), si no `Unavailable`, si no `Allow` con el `remaining` mínimo |
| `Throttle::record_failure` | `fn record_failure(&self, key: &str, now: u64) -> Result<ThrottleOutcome, StoreError>` |
| `Throttle::record_success` / `reset` / `purge_expired` | `fn record_success(&self, key: &str) -> Result<(), StoreError>` / `fn reset(&self, key: &str) -> Result<(), StoreError>` / `fn purge_expired(&self, now: u64) -> Result<usize, StoreError>` |
| `ThrottleConfig` | `threshold` 5, `window_secs` 60, `ban_secs` 900 |
| `ThrottleDecision` | `Allow { remaining }` \| `Banned { until }` \| `Unavailable` — solo lo producen `check` / `check_any` |
| `ThrottleOutcome` | `Allow { remaining }` \| `Banned { until }` — resultado de `record_failure`; sin `Unavailable`, porque allí un fallo del almacén llega como `Err(StoreError)` |
| `ThrottleStore` | trait del almacenamiento de contadores; `MemoryThrottleStore` es la implementación en memoria incluida |
| `RiskLevel` | `None` \| `Low` \| `Medium` \| `High` \| `Critical` |
| `RiskAssessment` | resultado de `Scanner::assess` |
| `Scanner::assess` | `fn assess(&self, input: &str) -> RiskAssessment` |

Nota: `ThrottleDecision::Allow { remaining: 0 }` significa que **esta** petición debe rechazarse — el cupo está agotado, no es «queda un intento». La variante se llama `Allow` y no `Banned` porque en ese instante no hay ningún bloqueo activo. `Unavailable` solo lo producen `check` / `check_any`; `record_failure` devuelve `ThrottleOutcome`, que deliberadamente carece de esa variante: un fallo del almacén se convierte allí en `Err(StoreError)`.

El llamador rellena por completo un `RequestContext`: la biblioteca no incorpora una base geográfica ni valida firmas; solo compara los valores recibidos con la base registrada en `bind`.

`subject` **solo lo usa `bind`; `verify` lo ignora por completo** — la identidad que se comprueba en cada petición procede siempre del `SessionRecord` del servidor (el historial de ubicaciones remotas se agrega sobre `record.subject`), y el valor que envía el solicitante no es de fiar. Por eso `subject: ""` desde un middleware es válido (`bind` sí exige un valor no vacío). Y por eso mismo **nunca** debe ponerse aquí un identificador de usuario tomado de una cabecera de la petición: hoy no llega a la decisión, pero una refactorización futura no está obligada a mantenerlo así.

**El número de sujetos no tiene tope en el backend en memoria.** `MemoryStore` limita el historial de inicio de sesión de cada sujeto a `MAX_LOGINS_PER_SUBJECT` = 10, pero **nada limita el número de sujetos** (`Mutex<HashMap>`, sin hilo de fondo, entradas que solo crecen). Un proceso de larga vida debería llamar a `purge_expired` cada cierto intervalo, del orden de `ttl_secs`: borra las sesiones con `expires_at <= now` y todo el historial de inicio de sesión de los sujetos cuyo último punto de inicio de sesión sea anterior a `now - LOGIN_HISTORY_KEEP_SECS` (7 días). **El valor de retorno solo cuenta sesiones**, nunca el historial recuperado. Recuperar el historial de un sujeto inactivo le cuesta a ese sujeto una comprobación menos de ubicación remota / viaje imposible en su siguiente inicio de sesión: eso es un falso negativo y no un falso positivo, y después el historial se reconstruye de inmediato.

## Rutas de los módulos

| Módulo | Ruta | N.º de detectores |
|------|------|---------|
| Núcleo | `src/lib.rs` `result.rs` `scanner.rs` | — |
| Inyección | `src/injection/` | 11 |
| Protocolo | `src/protocol/` | 11 |
| Datos | `src/data/` | 7 |
| Archivos | `src/file/` | 3 |
| Mascota | `src/pet.rs` | — |

## Límites conocidos

Los siguientes puntos son límites **conocidos y deliberadamente mantenidos**, no defectos pendientes de arreglo. Antes de tocarlos, lee la justificación: cada uno se apoya en mediciones, y cada uno ya ha frenado un intento de endurecerlo.

### `dns_rebinding` solo reporta, no bloquea

Su criterio es «en la cabecera `Host:` aparece una dirección interna» — y esa misma forma es la de toda llamada pod a pod en k8s (`Host: 10.244.1.5:8080`), la de todo desarrollo local (`Host: localhost:8000`) y la de toda petición en la red de contenedores de Docker (`172.18.0.2`). El rebinding real es «un dominio público + un resultado de resolución que apunta hacia dentro», y el `Host` que envía el navegador es precisamente ese nombre público: **una sola cadena no contiene historial de resolución**, así que la forma que prueba este detector no se solapa con la forma del ataque. Por eso el detector es enteramente débil y siempre reporta `Low`; por muchas coincidencias que se apilen, nunca cruza la línea de rechazo por sí solo. La protección va después de la resolución, comparando la IP resultante, no en la capa de cadenas.

### Esta librería no puede escanear su propio código fuente, sus pruebas ni su documentación

El techo del escáner de firmas: medido sobre este repositorio, 78 de 298 archivos cruzan la línea de rechazo, y todos ellos contienen cadenas de ataque **por construcción**: cargas de prueba, los propios literales de expresión regular del código de los detectores y las tablas de README/OWASP que nombran esos patrones. Un README no es defectuoso por listar `(a+)+`. Escanear tus propios artefactos exige excluir antes ese corpus, o elegir otro criterio.

### `upload` reporta `<%@` / `<?php` como Critical allí donde aparezcan

El contrato de este detector es «**este blob es código ejecutable en el servidor**»: la mera presencia lo establece, así que no hay reparto en niveles. Una página JSP y un webshell JSP comparten su preámbulo byte a byte (`<%@ page language="java" … %>` y `<%@ page import="java.io.*" %>` son la misma forma); degradar `<%@`/`<%=` dejaría los webshells por debajo de la línea de rechazo, es decir, borrar con otro nombre. El precio: escanear una página **que se está sirviendo** (y no un archivo subido) también coincide; eso es un dominio de entrada inadecuado.

### `path_traversal` reporta `(?:\.\./){2,}` como Critical

Una ruta relativa profunda en un monorepo (`from '../../../shared/domain'`) coincide. No se endurece más porque la única restricción que la separa de un ataque es una lista de nombres de archivo objetivo (`../etc/passwd` y compañía), y esa solo cubre archivos del sistema: el atacante simplemente elige otro objetivo de LFI.

## Rendimiento

Cada detector guarda sus patrones en una tabla estática `static PATTERNS: LazyLock<Vec<Regex>>`: cada expresión regular se compila una sola vez, en su primer uso dentro del proceso, y se reutiliza en cada llamada posterior, sin coste de compilación añadido. El escaneo completo con los 32 detectores tarda decenas de microsegundos por operación, y ese coste crece con el número de detectores y la longitud de la entrada. Mide el valor real en tu propio hardware y con tu carga de trabajo. Adecuado para escenarios de alto rendimiento (puertas de enlace de API, pipelines de logs).
