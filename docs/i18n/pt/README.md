<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust

**🌐 [中文 (原文)](../../../README.md)**

Biblioteca de detecção de ataques escrita em Rust, cobrindo 4 categorias principais — ataques de injeção, ataques de protocolo, ataques de dados/serialização e vazamento de arquivos/dados sensíveis — com um total de 32 detectores. Zero dependência de frameworks externos: a cadeia de detectores trabalha apenas com strings, complementada por três módulos com estado (veja abaixo).

O mascote do projeto, **甲哨 Sentri** ([`pet.svg`](../../pet.svg)) — 32 placas de carapaça para 32 detectores. Reporta tudo, não bloqueia nada.

---

## Mascote do Projeto: 甲哨 Sentri

<img src="../../pet.svg" alt="甲哨 Sentri — o mascote do projeto security-rust" width="340">

Um caranguejo-sentinela segurando uma lupa e uma placa. O personagem não é decoração — é o design desta biblioteca, desenhado:

| Elemento | O que ele representa |
|---------|---------|
| 4 fileiras × 8 placas de carapaça | 32 detectores sem estado; as 4 fileiras são injeção / protocolo / dados / arquivos |
| A lupa na pinça esquerda | **Ver** — `Detector::detect()` apenas varre; um acerto devolve uma evidência |
| A placa na pinça direita (`已上报` — "reportado") | **Reportar** — devolve `DetectionResult`, nunca lança exceção, nunca interrompe a cadeia de chamadas |
| Pinças que nunca apertam | A decisão é do chamador; a única exceção é o `SessionGuard`, que realmente faz `Block` |
| O monóculo | Mania de auditor: todo resultado traz `matched_pattern` e `offset`, apontando para o ponto exato da entrada original |
| `deps: regex ×1` na placa de identificação | A promessa de zero dependências: `[dependencies]` é sempre apenas `regex` |

Lema: **reportar tudo, não bloquear nada.**

A arte é embutida na crate com `include_str!` (sem custo em tempo de execução — não é linkada se não for usada), e a versão ASCII vai direto para o terminal ou o log:

```rust
println!("{}", security_rust::pet::ASCII);
```

---

## Estrutura do Projeto

```
security-rust/
├── src/
│   ├── lib.rs              trait Detector (o único contrato), helper regex_detect, docs da crate
│   ├── scanner.rs          Scanner / ScannerBuilder: monta os 32 detectores por padrão
│   ├── result.rs           DetectionResult / AttackCategory / Severity
│   ├── score.rs            Pontuação de risco: soma ponderada + faixas → RiskAssessment
│   ├── pet.rs              O mascote do projeto (NAME / TAGLINE / ASCII / SVG)
│   ├── injection/          11 detectores de injeção
│   ├── protocol/           11 detectores de protocolo
│   ├── data/               7 detectores de dados
│   ├── file/               3 detectores de arquivos
│   ├── session/            SessionGuard + SessionStore (guard / store / geo)
│   └── throttle/           Throttle + ThrottleStore (guard / store)
├── tests/                  7 suítes de integração: sessão, limitação de taxa, ciclo de vida, invariantes, robustez, ponta a ponta, limite por múltiplas chaves
├── examples/
│   ├── waf.rs              Exemplo de pipeline ponta a ponta (varredura → limitação de taxa → sessão → ação)
│   └── axum_middleware.rs  Referência de integração do middleware axum
├── docs/
│   ├── API.md              Referência completa da API
│   ├── OWASP-COVERAGE.md   Matriz de cobertura contra as classes de ataque do OWASP
│   ├── pet.svg             A arte do mascote do projeto
│   ├── diagrams/           Diagramas de arquitetura / funcionalidades / ciclo de vida (SVG)
│   ├── i18n/               READMEs e documentos de API em 12 idiomas
│   └── ...                 QR codes de doação, relatórios de revisão de código e de testes
└── Cargo.toml              A única dependência de execução: regex
```

---

## Filosofia de Design

### Por que «detecção» em vez de «bloqueio»

Esta biblioteca se posiciona como um **scanner de entrada puro** — recebe strings e retorna resultados de detecção estruturados. Não está vinculada a nenhum framework web, não faz parsing de requisições/respostas HTTP e não implementa bloqueio em tempo real. Assim, você pode incorporá-la em qualquer pipeline: mecanismos de regras WAF, auditoria de logs, validação prévia em gateways de API, ferramentas CLI de varredura de segurança, etc. Os módulos `session`, `throttle` e `score` (veja abaixo) vão além: mantêm estado ou agregam sinais, e continuam sem depender de nenhum framework.

### Princípios de Arquitetura

- **Responsabilidade única** — cada detector cuida de apenas um tipo de ataque e mantém internamente um conjunto de padrões regex pré-compilados
- **Interface unificada** — o trait `Detector` é o único contrato de todos os detectores: `fn detect(&self, input: &str) -> Option<DetectionResult>`
- **Cobertura padrão** — `Scanner::default()` monta todos os 32 detectores com um único comando, utilizável sem configuração
- **Configuração opcional** — `Scanner::builder()` suporta personalização sob demanda, montando detectores seletivamente via `.with_detector()`

### Compensações

| Decisão | Escolha | Motivo |
|------|------|------|
| Regex vs parser | Regex | Em cenários de detecção, a velocidade é prioridade; regex cobre melhor padrões deformados/contornados |
| Primeiro que chegar vs detecção completa | Detecção completa | Uma entrada pode acionar vários tipos de ataque simultaneamente; não se deve deixar de reportar |
| Zero dependências vs adotar serde | Zero dependências | Depende apenas de `regex`, compilação rápida e tamanho pequeno |
| Detectores vs módulos com estado | Separados | `Detector::detect(&str)` só recebe uma string e não expressa uma entrada composta de «token + impressão digital + posição + tempo»; por isso `session` / `throttle` ficam independentes do `Scanner` |
| fail-closed vs fail-open | Autenticação fail-closed, limitação de taxa fail-open | Deixar passar uma decisão de sessão equivale a ser contornado, então é preciso bloquear; já bloquear todos os usuários na limitação de taxa é auto-DoS, e a barreira principal de autenticação continua barrando — a decisão fica com o chamador |

---

## Arquitetura de Design

<img src="../../diagrams/architecture.svg" alt="security-rust — arquitetura: chamador → camada de detecção → camada de pontuação → camada de guarda → armazenamento" width="900">

Cinco camadas, de cima para baixo: **chamador** (WAF / gateway / auditoria / CLI) → **camada de detecção** (`Scanner` mantendo um `Vec<Box<dyn Detector>>`, 32 detectores em 4 categorias) → **camada de pontuação** (`score::assess`) → **camada de guarda** (`SessionGuard` / `Throttle`, cada um ligado a um trait de armazenamento) → **abstração de armazenamento** (`MemoryStore` embutido; o Redis é implementado pelo chamador).
*(As anotações do diagrama estão em chinês; os rótulos são nomes de API.)*

O trait `Detector` é o único contrato da camada de detecção: `fn detect(&self, input: &str) -> Option<DetectionResult>`. `session`, `throttle` e `score` não o implementam — a entrada deles não é uma única string (token + impressão digital + localização + tempo), ou eles consomem resultados de varredura em vez da entrada bruta — por isso respondem por conta própria, como documentado abaixo. A linha vermelha de retorno à direita marca a fronteira da biblioteca: **o veredito volta para o chamador executar**; a biblioteca nunca toca na requisição.

### Responsabilidades dos Módulos

| Módulo | Caminho | Nº de detectores | Responsabilidade |
|------|------|---------|------|
| Núcleo | `src/lib.rs` `result.rs` `scanner.rs` | — | `Detector` trait, `DetectionResult`, `Scanner`/`ScannerBuilder` |
| Injeção | `src/injection/` | 11 | XSS, SQL injection, injeção de comandos, NoSQL, LDAP, XPATH, JNDI, SSI, GraphQL, SSTI, string de formato |
| Protocolo | `src/protocol/` | 11 | SSRF, XXE, injeção de cabeçalho, ataque de Host header, request smuggling, open redirect, CORS, WebSocket, DNS rebinding, Log4Shell, poluição de parâmetros HTTP |
| Dados | `src/data/` | 7 | Desserialização PHP, injeção de fórmula CSV, injeção de cabeçalho de e-mail, ataques JWT, poluição de protótipo, injeção de fórmulas, ReDoS |
| Arquivos | `src/file/` | 3 | Path traversal, upload malicioso de arquivos, vazamento de dados sensíveis |
| Sessão | `src/session/` | — | `SessionGuard`: sequestro de cliente, adulteração de dados, login de local incomum / viagem impossível, sessões com token |
| Limitação de taxa | `src/throttle/` | — | `Throttle`: contagem em janela deslizante, banimento por limiar, bloqueio de conta |
| Pontuação | `src/score.rs` | — | `RiskAssessment`: agrega várias detecções de baixa gravidade em uma grandeza mensurável |

### Estrutura do Resultado de Detecção

`DetectionResult` retorna estruturadamente os seis campos `attack_type`, `category`, `severity`, `matched_pattern`, `offset`, `message`. Definição completa em [Referência da API](./API.md).

---

## Funcionalidades Implementadas

<img src="../../diagrams/features.svg" alt="security-rust — funcionalidades: injeção 11, protocolo 11, dados 7, arquivos 3, mais três módulos com estado" width="900">

Os 32 detectores são montados por categoria e habilitados por padrão via `Scanner::default()` sem nenhuma configuração. As tabelas abaixo listam o que cada um cobre e sua severidade. A severidade descreve um único acerto; o risco agregado é o que `Scanner::assess()` retorna.
*(As anotações do diagrama estão em chinês; os rótulos são nomes de API.)*

### Ataques de Injeção (11 detectores)

| Detector | Padrões cobertos | Severidade |
|--------|---------|---------|
| **xss** | `<script>`, manipuladores de eventos como `onerror=`, protocolo pseudo `javascript:`, tags `<svg>`/`<iframe>`, `expression()` de CSS, `eval()`, `document.cookie` | Critical |
| **sql_injection** | `UNION SELECT`, injeção de atraso `sleep()`/`benchmark()`/`pg_sleep()`, enumeração `information_schema`, stored procedures `exec sp_`/`xp_`, padrões de blind boolean `' OR '1'='1`, `LOAD_FILE()`/`INTO OUTFILE` | Critical |
| **command_injection** | Comandos com crase, subcomandos `$()`, execução em cadeia com pipe, reverse shell `/dev/tcp`, funções PHP `passthru()`/`shell_exec()`/`system()`, chamadas `cmd.exe`/`powershell` | Critical |
| **nosql_injection** | Operadores MongoDB `$ne`/`$gt`/`$regex`/`$where`, injeção `$or`, bypass de autenticação `{"$gt": ""}` | Critical |
| **ldap_injection** | Operadores de filtro `(&` `(\|` `(!`, enumeração de atributos `*(cn=`, injeção `objectClass`/`uid` | High |
| **xpath_injection** | Bypass booleano `' or '1'='1`, injeção de função `' or true()`, travessia de nós `'] \| '` | High |
| **jndi_injection** | `${jndi:ldap://`, ofuscação `${lower:j}`, ofuscação `${upper:j}`, ofuscação de string vazia `${::-j}`, consulta de variáveis de ambiente `${env:}`, propriedades de sistema `${sys:}` | Critical |
| **ssi_injection** | Execução de comandos `<!--#exec cmd=`, inclusão de arquivos `<!--#include file=`, saída de variáveis `<!--#echo var=`, informações de arquivo `<!--#fsize`/`<!--#flastmod` | High |
| **graphql_injection** | Consultas de introspecção `__schema`/`__type`, DoS de aninhamento profundo (≥5 níveis) | Medium |
| **ssti** | Jinja2 `{{ }}` / FreeMarker `${ }` — **avaliação dentro dos delimitadores** (`{{7*7}}`, `${7*7}`, `{{config`, `${T(java.lang.Runtime)}`), ERB `<%=` `<%@`, Velocity `#set()`, cadeias de escape do Python `__mro__`/`__subclasses__()`/`__globals__`/`__builtins__`/`__class__`/`__dict__`; os delimitadores sozinhos não são sinal, um simples marcador como `${x}` não é reportado | Critical |
| **format_string** | especificadores de escrita `%n` (inclusive com modificadores de comprimento), larguras exageradas `%123456d`, especificadores `%x`/`%p`/`%s` repetidos (vazamento de string de formato / corrupção de memória) | Medium |

### Ataques de Protocolo e Requisição (11 detectores)

| Detector | Padrões cobertos | Severidade |
|--------|---------|--------|
| **ssrf** | Metadados de nuvem `169.254.169.254`, IPs internos RFC1918 (10.x, 172.16-31.x, 192.168.x), loopback `127.x`, loopback IPv6 `::1`, `0.0.0.0`, protocolos perigosos `gopher://`/`dict://`/`ftp://`/`file://` | Critical |
| **xxe** | Declarações de entidade `<!ENTITY`, referências externas `SYSTEM`/`PUBLIC`, entidades de parâmetro `%`, declarações DTD `<!DOCTYPE` | Critical |
| **header_injection** | CRLF codificado em URL `%0d%0a`, injeção CRLF bruto `\r\n` | High |
| **host_header** | Injeção de múltiplos Host headers, envenenamento `X-Forwarded-Host`/`X-Original-URL`/`X-Rewrite-URL`, Host com CRLF | High |
| **request_smuggling** | Cabeçalhos duplos `Transfer-Encoding`, contrabando `Content-Length: 0`, ofuscação de término chunked `\r\n0\r\n` | High |
| **open_redirect** | URLs relativas de protocolo `//evil.com`, redirecionamento por protocolos pseudo `javascript:`/`data:text/html` | Medium |
| **cors** | `Access-Control-Allow-Origin: null`, `Origin: null` (o indicador canônico de iframes em sandbox e CSWSH) e `Access-Control-Allow-Origin: *` **junto com** `Access-Control-Allow-Credentials: true`. Isoladamente, ambos são normais em APIs públicas e recursos estáticos e não são reportados | Medium |
| **websocket** | `Origin: null` junto com um upgrade WebSocket (CSWSH), `ws://` para endereços de loopback/privados/link-local (incluindo o endpoint de metadados de nuvem `169.254.169.254`) | High |
| **dns_rebinding** | Host header com IPs internos `127.x`/`10.x`/`192.168.x`/`172.16-31.x`, `localhost`, `::1`, `0.0.0.0` | High |
| **log4shell** | ofuscação de lookup `${lower:j}`/`${upper:j}`, ofuscação com string vazia `${::-j}`, lookups aninhados `${${...}:...}`, variante codificada em URL `%24%7b...%7d...ndi` | Critical |
| **hpp** | mistura de separadores na query string `&a=1;b=2` e `;a=1&b=2` (poluição de parâmetros por divergência entre parsers) | Medium |

### Ataques de Dados e Serialização (7 detectores)

| Detector | Padrões cobertos | Severidade |
|--------|---------|--------|
| **deserialization** | Objetos serializados PHP `O:número:`/`C:número:`, arrays `a:número:{`, chamadas `unserialize()`, métodos mágicos `__wakeup`/`__destruct`/`__toString` | Critical |
| **csv_injection** | Caracteres de fórmula no início da célula `=`/`+`/`-`/`@` (tabulação e retorno de carro são **separadores**, não inícios de fórmula), um `=` imediatamente após um separador `,`/`;`/`\t`, troca dinâmica de dados DDE, pipe de comandos `cmd\|`, funções `@SUM()` | Medium |
| **mail_header** | Injeção Bcc:`/`Cc:` cópia oculta, múltiplos remetentes `From:`, injeção de cabeçalhos MIME `MIME-Version:`/`Content-Type: multipart`, manipulação de limite `boundary=` | Medium |
| **jwt_attack** | Bypass de algoritmo vazio `alg: none`, injeção de path traversal `kid`, segmento de assinatura vazio, segmento de payload vazio | High |
| **prototype_pollution** | Poluição da cadeia de protótipos `__proto__`/`constructor.prototype`, sequestro de propriedades `__defineGetter__`/`__defineSetter__`/`__lookupGetter__`/`__lookupSetter__` | High |
| **formula_injection** | caracteres de fórmula no início do campo com pipe de comando `=cmd\|`, funções de planilha perigosas `HYPERLINK`/`IMPORTXML`/`IMPORTDATA`/`IMPORTRANGE`/`WEBSERVICE`/`RTD`/`EXEC`, exfiltração via `\|` + referência de célula `A0`, chamadas `DDE(`, funções `@` | High |
| **redos** | backtracking catastrófico: quantificadores aninhados `(a+)+`/`(a{2,})+`, alternativas sobrepostas `(a\|ab)+`, quantificador sobre grupo com `\w`/`\d`/`.` | Medium |

### Arquivos e Dados Sensíveis (3 detectores)

| Detector | Padrões cobertos | Severidade |
|--------|---------|--------|
| **path_traversal** | Travessia de diretórios `../`/`..\\`, bypass de codificação URL `%2e%2e`, wrappers de protocolo `php://filter`/`php://input`/`phar://`/`zip://`/`data://`/`expect://`/`glob://`, truncamento por byte nulo `%00` | Critical |
| **upload** | Tags PHP `<?php`/`<?=`, tags ASP `<%@`/`<%=`, padrões de backdoor `eval($_`/`system($_`/`exec($_`/`passthru($_`, superglobais `$_GET`/`$_POST`/`$_REQUEST`/`$_SERVER`, bypass de codificação `base64_decode()` | Critical |
| **data_leak** | PAN de cartão de crédito com 16 dígitos (Visa/MasterCard/AmEx/Discover/JCB/Diners), AWS Access Key `AKIA...`, cabeçalho de chave privada PEM `-----BEGIN`, chaves de API OpenAI/LLM `sk-...`, strings de conexão de banco `mongodb://`/`mysql://`/`postgresql://`/`redis://`/`jdbc:`, Token JWT | Critical |

---

## Módulos com Estado

`session`, `throttle` e `score` **não** são implementações de `Detector`. `session` e `throttle` têm estado e estão ligados a uma identidade — `Detector::detect(&self, input: &str)` não consegue expressar uma entrada composta de token, impressão digital, posição e tempo. Por isso ficam ao lado da cadeia de detectores, não dentro dela.

| Módulo | Tipo | Responsabilidade |
|------|------|------|
| `session` | `SessionGuard<S: SessionStore>` | Segurança de sessão: sequestro de cliente, adulteração de dados, login de local incomum, sessões com token. Métodos `bind`/`verify`/`revoke`/`revoke_all`/`rotate`; `Decision { Allow, Challenge, Block }` + `SessionThreat`; `SessionConfig` (`ttl_secs` 3600, `impossible_travel_kmh` 900.0, `timestamp_skew_secs` 300); trait `SessionStore` + `MemoryStore` |
| `throttle` | `Throttle<S: ThrottleStore>` | Limitação de taxa e banimento: janela deslizante, banimento por limiar, bloqueio de conta. Métodos `check`/`check_any`/`record_failure`/`record_success`/`reset`/`purge_expired`; `ThrottleDecision { Allow { remaining }, Banned { until }, Unavailable }`; `ThrottleConfig` (`threshold` 5, `window_secs` 60, `ban_secs` 900); `record_failure` devolve `ThrottleOutcome` (`Allow`/`Banned`), sem `Unavailable` |
| `score` | `RiskLevel`, `RiskAssessment`, `Scanner::assess()` | Avaliação de risco: agrega sinais isolados de baixa gravidade em uma grandeza mensurável. `RiskLevel { None, Low, Medium, High, Critical }` |

**A assimetria diante de falhas é intencional.** `SessionGuard` retorna `Decision::Block` (`StoreUnavailable`) quando o armazenamento falha — fail-closed, nunca libera. `Throttle` é a exceção consciente: limitação de taxa é defesa em profundidade e não uma barreira de autenticação principal; por isso uma falha do backend retorna `ThrottleDecision::Unavailable` e não `Banned` — bloquear todo mundo seria um auto-DoS. A decisão fica com o chamador.

**Continuam sem novas dependências:** a lista se resume a `regex`. O preço: o token e a assinatura vêm do chamador, e as posições são interpretadas pelo chamador. Os dois módulos abstraem o armazenamento atrás de um trait — para implantação com múltiplas instâncias basta implementar `SessionStore`/`ThrottleStore` sobre Redis.

---

## Ciclo de Vida

<img src="../../diagrams/lifecycle.svg" alt="security-rust — três ciclos de vida: varredura, sessão, limitação de taxa" width="900">

Três ciclos de vida independentes, cujo único ponto de encontro é a função de tratamento de requisições do chamador:
*(As anotações do diagrama estão em chinês; os rótulos são nomes de API.)*

| Ciclo de vida | Começa em | Termina em | Onde fica o estado |
|---------|------|------|---------|
| **Varredura** | `Scanner::scan(&str)` | `Vec<DetectionResult>` → `score::assess` → `RiskAssessment` | Nada — sem estado, independente a cada chamada |
| **Sessão** | `SessionGuard::bind()` grava um `SessionRecord` | `verify()` a cada requisição → `SessionVerdict` ⇒ `Allow` / `Challenge` / `Block` | `SessionStore` (com `MemoryStore` embutido) |
| **Limitação de taxa** | `Throttle::check_any(&[keys])` | `Allow{remaining}` / `Banned{until}` / `Unavailable` | `ThrottleStore` (com `MemoryThrottleStore` embutido) |

Duas bordas fáceis de errar:

- **`remaining == 0` significa que esta requisição deve ser rejeitada** — a cota acabou, não «ainda dá uma tentativa». Não inverta isso ao escrever os cabeçalhos `X-RateLimit-*`.
- **Falhas de armazenamento são tratadas em direções opostas**: o `SessionGuard` é fail-closed (`StoreUnavailable` ⇒ `Block`, nunca libera — caso contrário, um atacante que provoca uma falha no backend troca toda uma classe de verificações); o `Throttle` é fail-open (`Unavailable` vai para o chamador, porque bloquear todos os usuários numa oscilação do backend é auto-DoS, e a barreira principal `SessionGuard` continua bloqueando). Isto é uma decisão de design escrita, não uma proteção que faltou.

---

## Como Usar

Utilizável sem configuração:

```rust
use security_rust::Scanner;

let scanner = Scanner::default();
let results = scanner.scan("<script>alert('xss')</script>");
// [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
```

A pontuação de risco transforma a lista de acertos em um único nível, para que vários sinais de baixa gravidade não sejam ignorados em silêncio:

```rust
let assessment = scanner.assess("=cmd|' /C calc'!A0 `cat /etc/passwd` ../../../etc/passwd");
// assessment.level   >= RiskLevel::High
// assessment.results >= 3
// assessment.score   — pontuação bruta ponderada
```

Referência completa da API (instalação, varredura seletiva, configuração personalizada, pontuação de risco, exibição de severidade, segurança de sessão, limitação de taxa e banimento, desempenho) em [Referência da API](./API.md).

### Segurança de Sessão (`session`)

```rust
use security_rust::session::{Decision, MemoryStore, RequestContext, SessionConfig, SessionGuard};

let guard = SessionGuard::new(MemoryStore::new(), SessionConfig::default());

let login = RequestContext {
    token: "tok-abc",
    subject: "u-1",
    fingerprint: "ip=1.2.3.4|ua=curl",   // impressão digital do cliente, ligada no login
    location: Some("CN-BJ"),
    coords: Some((39.9042, 116.4074)),
    signature: None,                      // o MAC é assinado pelo chamador
    at: None,
};

// Login: cria a sessão + liga a impressão digital + registra a localização;
// um local incomum afeta apenas o veredito, não bloqueia o login
guard.bind(&login, 1_700_000_000).unwrap();

// Validação a cada requisição: o mesmo token com outra impressão digital ⇒ sequestro de cliente
let verdict = guard.verify(&RequestContext { fingerprint: "ip=5.6.7.8|ua=curl", ..login }, 1_700_000_010);

match verdict.decision {
    Decision::Allow => { /* deixar passar */ }
    Decision::Challenge => { /* deixar passar, mas exigir segundo fator: local incomum, desvio de relógio, assinatura inesperada */ }
    Decision::Block => { /* recusar */ }
}
```

### Limitação de Taxa e Banimento (`throttle`)

```rust
use security_rust::throttle::{MemoryThrottleStore, Throttle, ThrottleConfig, ThrottleDecision};

let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());
let key = "acct:u-1"; // a key é construída e normalizada pelo chamador; nunca use a entrada bruta como key
let now = 1_700_000_000;

// Uma requisição real tem duas dimensões: IP e conta. check_any pergunta as duas de uma vez e funde pelo mais estrito
match throttle.check_any(&["ip:1.2.3.4", key], now) {
    // remaining pode ir para X-RateLimit-*; **remaining == 0 significa que esta requisição deve ser recusada**
    ThrottleDecision::Allow { remaining } => { /* cota restante: remaining */ }
    // now >= until já conta como desbanido
    ThrottleDecision::Banned { until } => { /* banido; desbanimento em until */ }
    // falha do backend: este módulo não decide pelo chamador (recomendado: deixar passar + alertar)
    ThrottleDecision::Unavailable => { /* backend de limitação indisponível */ }
}

// Registra uma falha de autenticação: ao atingir o threshold, bane. Devolve ThrottleOutcome (dois estados),
// e uma falha de armazenamento vira Err — não é preciso escrever código para um braço Unavailable que nunca executa
let _ = throttle.record_failure(key, now);
```

---

## Desenvolvimento

```bash
# Compilar
cargo build --release

# Testes (494: 365 unitários + 128 de integração + 1 teste de documentação)
cargo test

# Exemplo de pipeline ponta a ponta (varredura → limitação de taxa → sessão → ação)
cargo run --example waf

# Verificação de código
cargo clippy -- -D warnings
```

---

## Doação / Patrocínio

Se este projeto foi útil para você, sinta-se à vontade para apoiá-lo com uma doação (voluntário).

| Alipay | WeChat Pay |
|--------|---------|
| ![Alipay](./alipay.png) | ![WeChat Pay](./weixinpay.png) |

### Transferência Global (Remessa Internacional)

【Informações do Beneficiário】
- Nome do beneficiário: WANG KEXUN
- Número da conta do beneficiário: 881015918251

【Banco do Beneficiário】
- ZA Bank SWIFT Code: AABLHKHHXXX
- Nome do banco: ZA Bank Limited
- Código do banco: 387
- Endereço do banco: Core F, Cyberport 3, 100 Cyberport Road, Hong Kong

【Banco Agente para Remessas Transfronteiriças (se necessário)】

Atenção: estas são informações do banco agente (banco intermediário) para remessas transfronteiriças, não do banco do beneficiário. Consulte o banco remetente se for necessário fornecer as informações do banco agente.

O banco agente para remessas em dólares de Hong Kong, renminbi e dólares americanos é o Citibank:
- Nome do banco: Citibank N.A. Hong Kong
- SWIFT Code: CITIHKHXXXX
- Código do banco: 006
- Nome da agência: Hong Kong Branch
- Código da agência: 391
- Endereço do banco: Citibank Tower, Citibank Plaza, 3 Garden Road, Central, Hong Kong

O banco agente para remessas em outras moedas é o BNY Mellon:
- Nome do banco: THE BANK OF NEW YORK MELLON
- SWIFT Code: IRVTUS3NXXX
- Endereço do banco: THE BANK OF NEW YORK MELLON, 240 GREENWICH STREET, NEW YORK, United States

---

## Licença

MIT — Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
