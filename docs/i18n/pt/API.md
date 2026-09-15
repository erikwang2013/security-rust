<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# Referência da API security-rust

[中文](../../README.md) | [English](../en/API.md) | [한국어](../ko/API.md) | [Русский](../ru/API.md) | [Deutsch](../de/API.md) | [Français](../fr/API.md) | [Español](../es/API.md) | [हिन्दी](../hi/API.md) | [العربية](../ar/API.md) | [বাংলা](../bn/API.md) | [Bahasa Indonesia](../id/API.md) | [日本語](../ja/API.md) | [Português (本页)](./API.md)

---

## Trait Principal

### `Detector`

O único contrato de todos os detectores:

```rust
pub trait Detector {
    fn name(&self) -> &str;
    fn detect(&self, input: &str) -> Option<DetectionResult>;
}
```

- `name()` — nome do detector (ex.: `"xss"`, `"sql_injection"`)
- `detect()` — escaneia a entrada; retorna `Some(DetectionResult)` em caso de correspondência, `None` caso contrário

## Estrutura do Resultado de Detecção

```rust
pub struct DetectionResult {
    pub attack_type: String,      // "xss", "sql_injection" ...
    pub category: AttackCategory, // Injection | Protocol | Data | File
    pub severity: Severity,       // Critical | High | Medium | Low
    pub matched_pattern: String,  // segmento específico do padrão correspondido
    pub offset: usize,            // deslocamento em bytes na entrada
    pub message: String,          // descrição legível por humanos
}
```

## Scanner

### Instalação

```toml
[dependencies]
security-rust = "1.1.0"
```

### Início Rápido

```rust
use security_rust::Scanner;

fn main() {
    // Zero configuração: monta todos os 32 detectores
    let scanner = Scanner::default();

    // Escaneia a entrada, retorna todos os ataques detectados
    let results = scanner.scan("<script>alert('xss')</script>");

    for r in &results {
        println!("[{}] {} — offset: {}, pattern: {}",
            r.severity, r.message, r.offset, r.matched_pattern);
    }
    // Saída:
    // [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
}
```

### Varredura Seletiva

```rust
let scanner = Scanner::default();

// Executa apenas os detectores especificados
let results = scanner.scan_with(
    "1 UNION SELECT password FROM users",
    &["sql_injection", "xss"],
);
```

### Configuração Personalizada

```rust
use security_rust::injection::{XssDetector, SqlInjectionDetector};

// Monta apenas os detectores necessários via builder
let scanner = Scanner::builder()
    .with_detector(Box::new(XssDetector))
    .with_detector(Box::new(SqlInjectionDetector))
    .build();
```

### Exibição de Severidade

```rust
use security_rust::Severity;

let r = &results[0];
println!("{}", r.severity);  // CRITICAL | HIGH | MEDIUM | LOW
```

Os demais rótulos de estado também implementam `Display` e saem em maiúsculas: `Decision` (`ALLOW` / `CHALLENGE` / `BLOCK`), `SessionThreat` (p. ex. `impossible travel (11205 km/h)`), `AttackCategory` (em minúsculas, p. ex. `injection`), `ThrottleDecision` (`ALLOW` / `BANNED` / `UNAVAILABLE`) e `ThrottleOutcome` (`ALLOW` / `BANNED`).

```rust
println!("{} {}", verdict.decision, verdict.threats.len());  // BLOCK 2
```

## Módulos com Estado

`session` e `throttle` **não** implementam o trait `Detector` de propósito: têm estado e estão ligados a uma identidade, e `Detector::detect(&self, input: &str)` não consegue expressar uma entrada composta de token, impressão digital, posição e tempo. `score` é um cálculo puro sobre `DetectionResult`.

```rust
use security_rust::{
    Decision, MemoryStore, MemoryThrottleStore, Scanner,
    SessionConfig, SessionGuard, SessionVerdict,
    Throttle, ThrottleConfig, ThrottleDecision, ThrottleOutcome,
};

// Proteção de sessão — fail-closed: Decision::Block se o armazenamento falhar
let sessions = SessionGuard::new(MemoryStore::new(), SessionConfig::default());
let verdict: SessionVerdict = sessions.verify(&ctx, now);
if verdict.decision == Decision::Block {
    // recusar
}

// Limitação de taxa — defesa em profundidade: Unavailable na falha, não Banned
let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());
match throttle.check("user:42", now) {
    ThrottleDecision::Allow { remaining: 0 } => { /* recusar: cota esgotada */ }
    ThrottleDecision::Allow { .. } => { /* deixar passar */ }
    ThrottleDecision::Banned { until } => { /* banido até `until` */ }
    ThrottleDecision::Unavailable => { /* decidir por conta própria */ }


// Fundir várias dimensões (p. ex. IP + conta): vence o resultado mais estrito
let merged = throttle.check_any(&["ip:203.0.113.7", "user:42"], now);
match throttle.record_failure("user:42", now) {
    Ok(outcome) => { /* ThrottleOutcome: Allow { remaining } | Banned { until } */ }
    Err(_) => { /* falha do armazenamento */ }
}
}

// Avaliação de risco: agregar sinais isolados em uma grandeza mensurável
let risk = Scanner::default().assess(input);
```

| Elemento | Assinatura / campo |
|------|------|
| `SessionGuard::bind` | `fn bind(&self, ctx: &RequestContext, now: u64) -> Result<SessionVerdict, SessionError>` |
| `SessionGuard::verify` | `fn verify(&self, ctx: &RequestContext, now: u64) -> SessionVerdict` |
| `SessionGuard::revoke` / `revoke_all` | `fn revoke(&self, token: &str) -> Result<(), StoreError>` / `fn revoke_all(&self, subject: &str) -> Result<usize, StoreError>` |
| `SessionGuard::rotate` | renova o token de uma sessão |
| `RequestContext` | `token`, `subject`, `fingerprint`, `location`, `coords`, `signature`, `at` |
| `SessionVerdict` | `decision: Decision`, `severity: Option<Severity>` (`None` quando liberado), `threats: Vec<SessionThreat>` |
| `Decision` | `Allow` \| `Challenge` \| `Block` |
| `SessionConfig` | `ttl_secs` 3600, `impossible_travel_kmh` 900.0, `timestamp_skew_secs` 300 |
| `SessionStore` | trait do armazenamento de sessões; `MemoryStore` é a implementação em memória fornecida |
| `Throttle::check` | `fn check(&self, key: &str, now: u64) -> ThrottleDecision` |
| `Throttle::check_any` | `fn check_any(&self, keys: &[&str], now: u64) -> ThrottleDecision` — funde várias dimensões: `Banned` vence (com o `until` mais tardio), senão `Unavailable`, senão `Allow` com o `remaining` mínimo |
| `Throttle::record_failure` | `fn record_failure(&self, key: &str, now: u64) -> Result<ThrottleOutcome, StoreError>` |
| `Throttle::record_success` / `reset` / `purge_expired` | `fn record_success(&self, key: &str) -> Result<(), StoreError>` / `fn reset(&self, key: &str) -> Result<(), StoreError>` / `fn purge_expired(&self, now: u64) -> Result<usize, StoreError>` |
| `ThrottleConfig` | `threshold` 5, `window_secs` 60, `ban_secs` 900 |
| `ThrottleDecision` | `Allow { remaining }` \| `Banned { until }` \| `Unavailable` — produzido apenas por `check` / `check_any` |
| `ThrottleOutcome` | `Allow { remaining }` \| `Banned { until }` — resultado de `record_failure`; sem `Unavailable`, porque ali uma falha do armazenamento vira `Err(StoreError)` |
| `ThrottleStore` | trait do armazenamento de contadores; `MemoryThrottleStore` é a implementação em memória fornecida |
| `RiskLevel` | `None` \| `Low` \| `Medium` \| `High` \| `Critical` |
| `RiskAssessment` | resultado de `Scanner::assess` |
| `Scanner::assess` | `fn assess(&self, input: &str) -> RiskAssessment` |

Atenção: `ThrottleDecision::Allow { remaining: 0 }` significa que **esta** requisição deve ser recusada — a cota acabou, e não «ainda resta uma tentativa». A variante se chama `Allow` e não `Banned` porque nesse instante não há banimento ativo. `Unavailable` só é produzido por `check` / `check_any`; `record_failure` devolve `ThrottleOutcome`, que deliberadamente não tem essa variante — uma falha do armazenamento vira `Err(StoreError)`.

O chamador preenche um `RequestContext` por completo: a biblioteca não traz uma base geográfica nem valida assinaturas; apenas compara os valores recebidos com a base registrada no `bind`.

`subject` **só é usado por `bind`; `verify` o ignora por completo** — a identidade verificada a cada requisição vem sempre do `SessionRecord` do servidor (o histórico de locais distantes agrega sobre `record.subject`), e o valor enviado pelo solicitante não é confiável. Por isso `subject: ""` vindo de um middleware é válido (`bind` é que exige valor não vazio). E é justamente por isso que **nunca** se deve colocar aqui um identificador de usuário tirado de um cabeçalho da requisição: hoje ele não chega à decisão, mas uma refatoração futura não é obrigada a manter isso.

## Caminhos de Módulos

| Módulo | Caminho | Nº de detectores |
|------|------|---------|
| Núcleo | `src/lib.rs` `result.rs` `scanner.rs` | — |
| Injeção | `src/injection/` | 11 |
| Protocolo | `src/protocol/` | 11 |
| Dados | `src/data/` | 7 |
| Arquivos | `src/file/` | 3 |

## Desempenho

Cada detector mantém seus padrões em uma tabela estática `static PATTERNS: LazyLock<Vec<Regex>>`: cada expressão regular é compilada uma única vez, no primeiro uso dentro do processo, e reutilizada a cada chamada seguinte, sem custo de compilação adicional. A varredura completa com os 32 detectores leva dezenas de microssegundos por varredura, e esse custo cresce com o número de detectores e o comprimento da entrada. Meça o valor real no seu próprio hardware e com a sua carga de trabalho. Adequado para cenários de alto throughput (gateways de API, pipelines de log).
