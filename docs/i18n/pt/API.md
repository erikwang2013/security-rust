<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# Referência da API security-rust

[中文](../../../README.md) | [English](../en/API.md) | [한국어](../ko/API.md) | [Русский](../ru/API.md) | [Deutsch](../de/API.md) | [Français](../fr/API.md) | [Español](../es/API.md) | [हिन्दी](../hi/API.md) | [العربية](../ar/API.md) | [বাংলা](../bn/API.md) | [Bahasa Indonesia](../id/API.md) | [日本語](../ja/API.md) | [Português (本页)](./API.md)

---

## Trait Principal

### `Detector`

O único contrato de todos os detectores:

```rust
pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
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

## Dois Níveis: Sinais Fortes e Fracos

18 dos 32 detectores dividem seus padrões em dois níveis (os estáticos `STRONG_PATTERNS` / `WEAK_PATTERNS` do código-fonte). A estrutura de campos de `DetectionResult` não muda; o que muda é o valor de `severity`:

| Nível | Critério | `severity` | Um único acerto cruza a linha de rejeição? |
|------|------|-----------|------------------|
| **Forte** | A forma em si só pode vir de um ataque | O nível declarado do detector | Sim |
| **Fraco** | O token *aparece* e pronto — é comum em conteúdo normal | Sempre `Severity::Low` (5 pontos) | **Não** |

Mesmo detector, mesmo `attack_type`, só muda `severity`; `detect()` testa primeiro o nível forte e recorre ao fraco, então **cada detector devolve no máximo um resultado**. Os sinais fracos continuam sendo detectados e não somem em silêncio.

`DetectionResult` não distingue os níveis: para saber se um acerto é forte ou fraco basta verificar `severity == Severity::Low` (o nível fraco é a única origem que reporta `Low`). O canal de referência rejeita a partir de 40 pontos (`risk.level >= RiskLevel::High`, veja [`examples/waf.rs:166`](../../../examples/waf.rs)); um sinal fraco isolado vale 5 e não chega nesse ramo.

Para enxergar o ataque por trás dos sinais fracos existe o `assess()`, que empilha os acertos de vários detectores:

```rust
let scanner = Scanner::default();

// Três sinais fracos de três detectores distintos — só o empilhamento chega a Medium (15 pontos), ainda abaixo de High
let a = scanner.assess("<script src=\"/app.js\"></script>\n../config\n__proto__");
assert_eq!(a.results, 3);
assert_eq!(a.score, 15);
assert_eq!(a.level, RiskLevel::Medium);
```

Exemplos de formas rebaixadas (a lista completa está nos `WEAK_PATTERNS` de cada detector): `<script src=...>`, um `../` de um único nível, `-2` no início da linha, um `__proto__` nu, `${env:}`, `X-Forwarded-Host`, `Host: localhost`, um `10.0.0.5` nu, `//evil.com`, `information_schema`.

O critério é a **forma**, não o nome do arquivo: para o mesmo `../`, um único nível (`../x`) reporta `Low` e vários níveis (`../../`) reportam `Critical` ([`src/file/path_traversal.rs`](../../../src/file/path_traversal.rs)). Até onde cada detector vai está nas tabelas abaixo e nas tabelas de funcionalidades do [README](./README.md).

## Scanner

### Instalação

```toml
[dependencies]
security-rust = "2.1.1"
```

### Início Rápido

```rust
use security_rust::Scanner;

fn main() {
    // Zero configuração: monta todos os 32 detectores
    let scanner = Scanner::default();

    // Escaneia a entrada, retorna todos os ataques detectados (no máximo um resultado por detector)
    let results = scanner.scan("<img src=x onerror=alert(1)>");

    for r in &results {
        println!("[{}] {} — offset: {}, pattern: {}",
            r.severity, r.message, r.offset, r.matched_pattern);
    }
    // Saída:
    // [CRITICAL] XSS cross-site scripting detected — offset: 11, pattern: onerror=

    // Um sinal fraco usa o mesmo detector e o mesmo attack_type, mas reporta Low
    let weak = scanner.scan("<script src=\"/app.js\"></script>");
    // [LOW] XSS tag present (weak signal) — offset: 0, pattern: <script>
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
    Decision, MemoryStore, MemoryThrottleStore, RequestContext, Scanner,
    SessionConfig, SessionGuard, SessionVerdict,
    Throttle, ThrottleConfig, ThrottleDecision, ThrottleOutcome,
};

let now = 1_700_000_000u64;
let ctx = RequestContext {
    token: "tok-1", subject: "user-42", fingerprint: "ip=203.0.113.7|ua=curl",
    location: Some("CN-BJ"), coords: Some((39.9042, 116.4074)), signature: Some("mac-abc"), at: Some(now),
};

// Proteção de sessão — fail-closed: Decision::Block se o armazenamento falhar
let sessions = SessionGuard::new(MemoryStore::new(), SessionConfig::default());
let verdict: SessionVerdict = sessions.verify(&ctx, now);
if verdict.decision == Decision::Block {
    // recusar
}

// Limitação de taxa — defesa em profundidade: Unavailable na falha, não Banned
let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());
match throttle.check("acct:user-42", now) {
    ThrottleDecision::Allow { remaining: 0 } => { /* recusar: cota esgotada */ }
    ThrottleDecision::Allow { .. } => { /* deixar passar */ }
    ThrottleDecision::Banned { until } => { /* banido até `until` */ }
    ThrottleDecision::Unavailable => { /* decidir por conta própria */ }
}

// Fundir várias dimensões (p. ex. IP + conta): vence o resultado mais estrito
let merged = throttle.check_any(&["ip:203.0.113.7", "acct:user-42"], now);
match throttle.record_failure("acct:user-42", now) {
    Ok(outcome) => { /* ThrottleOutcome: Allow { remaining } | Banned { until } */ }
    Err(_) => { /* falha do armazenamento */ }
}

// Avaliação de risco: agregar sinais isolados em uma grandeza mensurável
let risk = Scanner::default().assess("<script>alert('xss')</script>");
```

| Elemento | Assinatura / campo |
|------|------|
| `SessionGuard::bind` | `fn bind(&self, ctx: &RequestContext, now: u64) -> Result<SessionVerdict, SessionError>` |
| `SessionGuard::verify` | `fn verify(&self, ctx: &RequestContext, now: u64) -> SessionVerdict` |
| `SessionGuard::revoke` / `revoke_all` | `fn revoke(&self, token: &str) -> Result<(), StoreError>` / `fn revoke_all(&self, subject: &str) -> Result<usize, StoreError>` |
| `SessionGuard::rotate` | renova o token de uma sessão |
| `SessionGuard::purge_expired` | apaga as sessões expiradas e o histórico de login dos sujeitos inativos. **O valor de retorno conta apenas sessões**, não o histórico recuperado |
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

**O número de sujeitos não tem teto no backend em memória.** O `MemoryStore` limita o histórico de login de cada sujeito a `MAX_LOGINS_PER_SUBJECT` = 10, mas **nada limita o número de sujeitos** (`Mutex<HashMap>`, sem thread de fundo, entradas que só crescem). Um processo de vida longa deve chamar `purge_expired` em intervalos da ordem de `ttl_secs`: apaga as sessões com `expires_at <= now` e todo o histórico de login dos sujeitos cujo último ponto de login seja anterior a `now - LOGIN_HISTORY_KEEP_SECS` (7 dias). **O valor de retorno conta apenas sessões**, nunca o histórico recuperado. Recuperar o histórico de um sujeito inativo custa a esse sujeito uma verificação a menos de localização remota / viagem impossível no login seguinte: isso é um falso negativo e não um falso positivo, e depois o histórico se reconstrói de imediato.

## Caminhos de Módulos

| Módulo | Caminho | Nº de detectores |
|------|------|---------|
| Núcleo | `src/lib.rs` `result.rs` `scanner.rs` | — |
| Injeção | `src/injection/` | 11 |
| Protocolo | `src/protocol/` | 11 |
| Dados | `src/data/` | 7 |
| Arquivos | `src/file/` | 3 |
| Mascote | `src/pet.rs` | — |

## Limites Conhecidos

Os pontos a seguir são limites **conhecidos e deliberadamente mantidos**, não defeitos à espera de conserto. Antes de mexer neles, leia a justificativa: cada um se apoia em medições, e cada um já barrou uma tentativa de endurecimento.

### `dns_rebinding` Só Reporta, Não Bloqueia

Seu critério é «aparece um endereço interno no cabeçalho `Host:`» — e essa mesma forma é a de toda chamada pod a pod no k8s (`Host: 10.244.1.5:8080`), a de todo desenvolvimento local (`Host: localhost:8000`) e a de toda requisição na rede de contêineres do Docker (`172.18.0.2`). O rebinding de verdade é «um domínio público + um resultado de resolução apontando para dentro», e o `Host` que o navegador envia é justamente esse nome público: **uma única string não contém histórico de resolução**, então a forma que este detector testa não se sobrepõe à forma do ataque. Por isso o detector é inteiramente fraco e reporta sempre `Low`; por mais acertos que se empilhem, nunca cruza a linha de rejeição sozinho. A proteção vem depois da resolução, comparando o IP resultante, não na camada de strings.

### Esta Biblioteca Não Consegue Escanear o Próprio Código-Fonte, os Próprios Testes nem a Própria Documentação

O teto do escâner de assinaturas: medido neste repositório, 78 de 298 arquivos cruzam a linha de rejeição, e todos eles contêm strings de ataque **por construção**: cargas de teste, os próprios literais de expressão regular do código dos detectores e as tabelas de README/OWASP que nomeiam esses padrões. Um README não é defeituoso por listar `(a+)+`. Para escanear os próprios artefatos é preciso excluir antes esse corpus, ou escolher outro critério.

### `upload` Reporta `<%@` / `<?php` como Critical Onde Aparecerem

O contrato deste detector é «**este blob é código executável no servidor**»: a mera presença estabelece isso, então não há divisão em níveis. Uma página JSP e um webshell JSP compartilham o preâmbulo byte a byte (`<%@ page language="java" … %>` e `<%@ page import="java.io.*" %>` são a mesma forma); rebaixar `<%@`/`<%=` deixaria os webshells abaixo da linha de rejeição, ou seja, apagar com outro nome. O preço: escanear uma página **que está sendo servida** (e não um arquivo enviado) também casa; isso é um domínio de entrada inadequado.

### `path_traversal` Reporta `(?:\.\./){2,}` como Critical

Um caminho relativo profundo em um monorepo (`from '../../../shared/domain'`) casa. Não se endurece mais porque a única restrição que o separa de um ataque é uma lista de nomes de arquivo alvo (`../etc/passwd` e companhia), e essa cobre apenas arquivos do sistema: o atacante simplesmente escolhe outro alvo de LFI.

## Desempenho

Cada detector mantém seus padrões em uma tabela estática `static PATTERNS: LazyLock<Vec<Regex>>`: cada expressão regular é compilada uma única vez, no primeiro uso dentro do processo, e reutilizada a cada chamada seguinte, sem custo de compilação adicional. A varredura completa com os 32 detectores leva dezenas de microssegundos por varredura, e esse custo cresce com o número de detectores e o comprimento da entrada. Meça o valor real no seu próprio hardware e com a sua carga de trabalho. Adequado para cenários de alto throughput (gateways de API, pipelines de log).
