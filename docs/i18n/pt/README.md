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

### Dois Níveis: Sinais Fortes e Fracos

Um detector **não** reporta todo acerto com a severidade que declara. 18 dos 32 detectores dividem seus padrões em dois níveis (os estáticos `STRONG_PATTERNS` / `WEAK_PATTERNS` do código-fonte):

| Nível | Critério | Severidade reportada | Um único acerto cruza a linha de rejeição? |
|------|------|-----------|------------------|
| **Forte** | A forma em si só pode vir de um ataque | O nível declarado do detector | Sim |
| **Fraco** | O token *aparece* e pronto — é comum em conteúdo normal | Sempre `Severity::Low` (5 pontos) | **Não** |

Os dois níveis saem do mesmo detector e do mesmo `attack_type`; só muda `severity`. Os sinais fracos **continuam sendo detectados** e não somem em silêncio: aparecem em `scan()` e continuam acumulando em `assess()`.

A consequência para o chamador é direta: **um sinal fraco isolado não justifica uma rejeição.** O canal de referência ([`examples/waf.rs:166`](../../../examples/waf.rs)) rejeita com `risk.level >= RiskLevel::High` (40 pontos), e um sinal fraco vale 5 — não chega nesse ramo. Para enxergar o ataque por trás dos sinais fracos é preciso olhar o que `assess()` produz quando os acertos de vários detectores se empilham:

```rust
let scanner = Scanner::default();

// Três sinais fracos de três detectores distintos — só o empilhamento escala
let a = scanner.assess("<script src=\"/app.js\"></script>\n../config\n__proto__");
// a.results == 3, a.score == 15 (3 × Low) → RiskLevel::Medium
// continua abaixo de High; qualquer outro acerto na mesma requisição cruza a linha
```

Passam a ser sinal fraco os tokens em que «aparecer é normal»:

| Sinal fraco | Por que não pode rejeitar sozinho |
|--------|-------------------|
| `<script src=...>`, `<iframe>`, `<link>`, `expression(` | Estão em qualquer página web |
| Um `../` de um único nível | Caminhos relativos de qualquer arquivo-fonte |
| `-2`, `+1` no início da linha | Itens de lista Markdown, números negativos em prosa |
| Um `__proto__` nu (leitura do protótipo) | Qualquer JS que mexa na cadeia de protótipos |
| `${env:}` / `${sys:}` | Sintaxe válida de configuração do log4j2 |
| `X-Forwarded-Host`, `X-Original-URL` | Proxies reversos os acrescentam por conta própria |
| `Host: 10.244.1.5`, `Host: localhost` | Chamadas pod a pod no k8s, desenvolvimento local |
| `10.0.0.5`, `192.168.1.1`, `127.0.0.1` nus | `X-Forwarded-For`, `bind 127.0.0.1` |
| `//evil.com`, URL relativa ao protocolo | Comentários de código, links de CDN na documentação |
| `information_schema` | Logs de erro do PG, tutoriais de SQL |

Esta tabela é só um exemplo. O critério é a **forma**, não o nome do arquivo: para o mesmo `../`, um único nível (`../x`) é fraco e vários níveis (`../../`) são fortes ([`src/file/path_traversal.rs`](../../../src/file/path_traversal.rs)). A lista completa está nos `WEAK_PATTERNS` de cada detector e nas marcas `fraco` das tabelas abaixo.

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

Os padrões marcados como `fraco` nas tabelas são **sinais fracos**: reportam `Severity::Low` (5 pontos) e não cruzam a linha de rejeição sozinhos (veja a seção anterior). A coluna «Severidade» é o **teto** do detector; um detector com entradas `fraco` tem os dois níveis, e seus padrões fortes continuam reportando o nível declarado. Um detector inteiramente fraco (`dns_rebinding`) tem `Low` como teto.
*(As anotações do diagrama estão em chinês; os rótulos são nomes de API.)*

### Ataques de Injeção (11 detectores)

| Detector | Padrões cobertos | Severidade |
|--------|---------|---------|
| **xss** | Manipuladores de evento como `onerror=`/`onload=` (a tabela completa de handlers), pseudo-protocolos `javascript:`/`vbscript:` (só quando um caractere não branco segue o esquema); `fraco`: tags `<script src=...>`/`<iframe>`/`<embed>`/`<object>`/`<link>`, `expression(` do CSS | Critical |
| **sql_injection** | `UNION SELECT`, injeção por atraso `sleep()`/`benchmark()`/`pg_sleep()` (só em posição de instrução), procedures `exec sp_`/`xp_`, padrão de cegueira booleana `' OR '1'='1`, `LOAD_FILE()`/`INTO OUTFILE`, `DROP TABLE`/`INSERT INTO`, quebra por comentário (`UN/**/ION`); `fraco`: a mera palavra `information_schema` | Critical |
| **command_injection** | Shell reverso `/dev/tcp`, formas de chamada `passthru()`/`shell_exec()`/`system("…")`/`popen()`/`pcntl_exec()`, formas de chamada `powershell -Command`/`cmd.exe /c`; `fraco`: trechos entre crases, subcomandos `$()`, encadeamento com pipe/`\|\|`/`&&`, `exec(`, `>/dev/null`, leitor+caminho do tipo `cat /etc/passwd`, palavras nuas `cmd.exe`/`powershell` | Critical |
| **nosql_injection** | Operadores MongoDB `$ne`/`$gt`/`$regex`/`$where`, injeção `$or`, bypass de autenticação `{"$gt": ""}` | Critical |
| **ldap_injection** | Operadores de filtro `(&` `(\|` `(!`, enumeração de atributos `*(cn=`, injeção `objectClass`/`uid` | High |
| **xpath_injection** | Bypass booleano `' or '1'='1`, injeção de função `' or true()`, travessia de nós `'] \| '` | High |
| **jndi_injection** | O próprio lookup `${jndi:`, dobra de maiúsculas/minúsculas `${lower:j}`/`${upper:j}`, dobra por string vazia `${::-j}` (existe só para ofuscar `jndi`); `fraco`: `${env:}`/`${sys:}`/`${java:}` — sintaxe de lookup válida | Critical |
| **ssi_injection** | Execução de comando `<!--#exec cmd=`, inclusão `<!--#include file=` com caminho absoluto ou `..`, despejo de ambiente `<!--#printenv`; `fraco`: `<!--#echo var=`, `<!--#fsize`/`<!--#flastmod`, `<!--#config`, inclusões corriqueiras como `<!--#include file="header.html"` | High |
| **graphql_injection** | Introspecção em forma de consulta `__schema {`/`__type {` (a mera menção do nome do campo em prosa não é reportada); `fraco`: `__typename` (Apollo/Relay acrescentam em toda consulta), ≥5 níveis de chaves aninhadas | Medium |
| **ssti** | Jinja2 `{{ }}` / FreeMarker `${ }` — **avaliação dentro dos delimitadores** (`{{7*7}}`, `${7*7}`, `{{config`, `${T(java.lang.Runtime)}`, `${@Type@method}`), LFI de template via `{% include '/…'` / `..`, cadeias de escape dentro dos delimitadores `__mro__`/`__subclasses__()`/`__globals__`/`__builtins__`/`__class__`/`__dict__`, FreeMarker `?new(`; `fraco`: diretivas de template nuas `{% %}`/`<%=`/`<%@`/`#set(`, atributos mágicos nus; os delimitadores sozinhos não são sinal, um marcador simples como `${x}` não é reportado | Critical |
| **format_string** | especificadores de escrita `%n` (inclusive com modificadores de comprimento), larguras exageradas `%123456d`, especificadores `%x`/`%p`/`%s` repetidos (vazamento de string de formato / corrupção de memória) | Medium |

### Ataques de Protocolo e Requisição (11 detectores)

| Detector | Padrões cobertos | Severidade |
|--------|---------|--------|
| **ssrf** | Metadados de nuvem `169.254.169.254` e `metadata.google.internal` (sem contexto de URL), IPs internos em **posição de autoridade de URL** (depois de `//`) `10.x`/`172.16-31.x`/`192.168.x`/`127.x`, `//localhost`, `//0.0.0.0`, `//[::1]`, protocolos perigosos `gopher://`/`dict://`/`ftp://user@`/`file:///`; `fraco`: os mesmos literais internos em **posição que não é URL** (`X-Forwarded-For: 10.0.0.5`, `bind 127.0.0.1`, `{"host": "10.0.0.1"}` são idênticos byte a byte) | Critical |
| **xxe** | Declarações de entidade `<!ENTITY`, referências externas `SYSTEM`/`PUBLIC`, entidades de parâmetro `%`, declarações DTD `<!DOCTYPE` | Critical |
| **header_injection** | Cabeçalhos próprios da resposta precedidos de `\r\n`: `Set-Cookie`/`Location`/`Refresh`/`Status`/`WWW-Authenticate`, ou `%0d` junto com `%0a` (também na ordem inversa `%0a…%0d`). `Content-Length`/`Content-Type`/`Transfer-Encoding` são cabeçalhos de **requisição**, idênticos byte a byte aos de qualquer requisição bem formada, então deixaram de ser sinal (a forma codificada `%0d%0aContent-Length:` continua coberta por `%0d`+`%0a`) | High |
| **host_header** | **Dois** cabeçalhos `Host:` (a RFC 7230 §5.4 exige 400, dois analisadores leem valores diferentes); `fraco`: `X-Forwarded-Host`/`X-Original-URL`/`X-Rewrite-URL` — proxies acrescentam esses cabeçalhos por conta própria, idênticos byte a byte a uma falsificação do cliente (`X-Forwarded-For`/`X-Forwarded-Proto` não são reportados de forma alguma) | High |
| **request_smuggling** | Cabeçalhos duplos `Transfer-Encoding`, contrabando `Content-Length: 0`, ofuscação de término chunked `\r\n0\r\n` | High |
| **open_redirect** | Saltos por pseudo-protocolos `javascript:`/`data:text/html`/`data:text/plain` (esquema seguido de conteúdo); `fraco`: URLs relativas ao protocolo `//evil.com` — idênticas aos links de CDN em comentários de código e documentação | Medium |
| **cors** | `Access-Control-Allow-Origin: null` e `Access-Control-Allow-Origin: *` **junto com** `Access-Control-Allow-Credentials: true`; `fraco`: `Origin: null` na requisição (iframes em sandbox, URLs `data:` e arquivos locais têm exatamente essa origem — é preciso que um `ACAO: null` devolva para fechar). Separados, os dois são normais em APIs públicas e recursos estáticos e não são reportados | Medium |
| **websocket** | `Origin: null` junto com um upgrade WebSocket (CSWSH), `ws://` para endereços de loopback/privados/link-local (incluindo o endpoint de metadados de nuvem `169.254.169.254`) | High |
| **dns_rebinding** | Cabeçalho Host com IPs internos `127.x`/`10.x`/`192.168.x`/`172.16-31.x`, `localhost`, `[::1]`, `0.0.0.0`. **O detector é inteiramente fraco**: reporta sempre `Low` — veja «Limites Conhecidos» | Low |
| **log4shell** | ofuscação de lookup `${lower:j}`/`${upper:j}`, ofuscação com string vazia `${::-j}`, lookups aninhados `${${...}:...}`, variante codificada em URL `%24%7b...%7d...ndi` | Critical |
| **hpp** | Mistura dos separadores `&`/`;` (`?a=1&b=2;c=3`), em que duas camadas de analisadores obtêm números de parâmetros diferentes; `fraco`: chaves repetidas como `?id=1&id=2` — idênticas byte a byte a um parâmetro multivalorado legítimo como `?tag=rust&tag=web` | Medium |

### Ataques de Dados e Serialização (7 detectores)

| Detector | Padrões cobertos | Severidade |
|--------|---------|--------|
| **deserialization** | Objetos serializados PHP `O:número:`/`C:número:`, arrays `a:número:{`, chamadas `unserialize()`, métodos mágicos em **forma de chamada** (`__wakeup(`/`__destruct(`/`__construct(`/`__toString(`/`__get(`/`__set(`/`__call(`); `fraco`: nomes de métodos mágicos nus (a documentação que os comenta também é detectada) | Critical |
| **csv_injection** | Um `=` imediatamente depois de um separador `,`/`;`/`\t` e seguido de um caractere não branco (fórmula na segunda célula de uma linha TSV/CSV), `DDE` no início da linha, `cmd\|` no início da linha, `@SUM(` no início da linha; `fraco`: `=`/`+`/`-` no início da linha seguidos nem de branco nem de um símbolo da mesma família (`- item` como item de lista, `---` como linha divisória, `++i`, `= 5` não casam). O `@` saiu por completo do nível grosso (`@media`/`@import` são comuns em folhas de estilo); só resta `@SUM(`. A tabulação e o retorno de carro são **separadores**, não inícios de fórmula | Medium |
| **mail_header** | Dois cabeçalhos `From:` contíguos, `MIME-Version:` no início da linha (um nome ausente da tabela de campos HTTP); `fraco`: `Cc:`/`Bcc:` no início da linha — idênticos byte a byte a um e-mail encaminhado ou a um corpo de mensagem ingerido. `Content-Type: multipart` e `boundary=` foram **removidos** (`Content-Type: multipart/form-data` é o cabeçalho padrão de todo POST de upload de arquivo). O teto é Medium (15 pontos): **o detector não cruza a linha de rejeição sozinho** | Medium |
| **jwt_attack** | Bypass de algoritmo vazio `alg: none`, injeção de path traversal `kid`, segmento de assinatura vazio, segmento de payload vazio | High |
| **prototype_pollution** | `__proto__` como chave ou alvo de atribuição (`"__proto__":`, `[__proto__]`, `__proto__ = x`), `constructor.prototype`/`constructor[`, `__defineGetter__`/`__defineSetter__`/`__lookupGetter__`/`__lookupSetter__`, `hasOwnProperty[`; `fraco`: um `__proto__` nu (`obj.__proto__` é apenas como a linguagem lê um protótipo) | High |
| **formula_injection** | caracteres de fórmula no início do campo com pipe de comando `=cmd\|`, funções de planilha perigosas `HYPERLINK`/`IMPORTXML`/`IMPORTDATA`/`IMPORTRANGE`/`WEBSERVICE`/`RTD`/`EXEC`, exfiltração via `\|` + referência de célula `A0`, chamadas `DDE(`, funções `@` | High |
| **redos** | backtracking catastrófico: quantificadores aninhados `(a+)+`/`(a{2,})+`, alternativas sobrepostas `(a\|ab)+`, quantificador sobre grupo com `\w`/`\d`/`.` | Medium |

### Arquivos e Dados Sensíveis (3 detectores)

| Detector | Padrões cobertos | Severidade |
|--------|---------|--------|
| **path_traversal** | Escape **multinível** `(?:\.\./){2,}`/`(?:\.\.\\){2,}`, bypass por codificação de URL `%2e%2e`/`..%2f`/`..%5c`, wrappers de protocolo `php://filter`/`php://input`/`phar://`/`zip://`/`data://`/`expect://`/`glob://`, truncamento com byte nulo `%00`; `fraco`: um `../`/`..\` de um único nível (idêntico a um caminho relativo em código ou documentação) | Critical |
| **upload** | Tags PHP `<?php`/`<?=`, tags ASP `<%@`/`<%=`, padrões de backdoor `eval($_`/`system($_`/`exec($_`/`passthru($_`, superglobais `$_GET`/`$_POST`/`$_REQUEST`/`$_SERVER`, bypass de codificação `base64_decode()` | Critical |
| **data_leak** | PAN de cartão de crédito de 16 dígitos (Visa/MasterCard/AmEx/Discover/JCB/Diners), AWS Access Key `AKIA...`, cabeçalho de chave privada PEM `-----BEGIN`, API Keys OpenAI/LLM `sk-...`, strings de conexão de banco `mongodb://`/`mysql://`/`postgresql://`/`redis://` (**precisam de userinfo `@`**: `mysql://root:secret@db` é reportado; `redis://shared-memory` e `postgres://localhost:5432/app` são configuração comum e **não** são reportados), `jdbc:` (sem essa restrição), tokens JWT | Critical |

---

## Limites Conhecidos

Os pontos a seguir são limites **conhecidos e deliberadamente mantidos**, não defeitos à espera de conserto. Antes de mexer neles, leia a justificativa: cada um se apoia em medições, e cada um já barrou uma tentativa de endurecimento.

### `dns_rebinding` Só Reporta, Não Bloqueia

Seu critério é «aparece um endereço interno no cabeçalho `Host:`» — e essa mesma forma é a de toda chamada pod a pod no k8s (`Host: 10.244.1.5:8080`), a de todo desenvolvimento local (`Host: localhost:8000`) e a de toda requisição na rede de contêineres do Docker (`172.18.0.2`). O rebinding de verdade é «um domínio público + um resultado de resolução apontando para dentro», e o `Host` que o navegador envia é justamente esse nome público: **uma única string não contém histórico de resolução**, então a forma que este detector testa não se sobrepõe à forma do ataque e não há direção em que endurecê-lo. Por isso o detector é inteiramente fraco e reporta sempre `Low`; por mais acertos que se empilhem, nunca cruza a linha de rejeição sozinho. A proteção vem depois da resolução, comparando o IP resultante, não na camada de strings.

### Esta Biblioteca Não Consegue Escanear o Próprio Código-Fonte, os Próprios Testes nem a Própria Documentação

O teto do escâner de assinaturas: medido neste repositório, 78 de 298 arquivos cruzam a linha de rejeição, e todos eles contêm strings de ataque **por construção**: cargas de teste, os próprios literais de expressão regular do código dos detectores e as tabelas de README/OWASP que nomeiam esses padrões. Um README não é defeituoso por listar `(a+)+`. Para escanear os próprios artefatos é preciso excluir antes esse corpus, ou escolher outro critério.

### `upload` Reporta `<%@` / `<?php` como Critical Onde Aparecerem

O contrato deste detector é «**este blob é código executável no servidor**»: a mera presença estabelece isso, então não há divisão em níveis. Uma página JSP e um webshell JSP compartilham o preâmbulo byte a byte (`<%@ page language="java" … %>` e `<%@ page import="java.io.*" %>` são a mesma forma); rebaixar `<%@`/`<%=` deixaria os webshells abaixo da linha de rejeição, ou seja, apagar com outro nome. O preço: escanear uma página **que está sendo servida** (e não um arquivo enviado) também casa; isso é um domínio de entrada inadequado — a mensagem do acerto `Malicious file upload detected` o nomeia.

### `path_traversal` Reporta `(?:\.\./){2,}` como Critical

Um caminho relativo profundo em um monorepo (`from '../../../shared/domain'`) casa. Não se endurece mais porque a única restrição que o separa de um ataque é uma lista de nomes de arquivo alvo (`../etc/passwd` e companhia), e essa cobre apenas arquivos do sistema: o atacante simplesmente escolhe outro alvo de LFI.

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

// Sinal forte: a forma só pode vir de um ataque ⇒ a severidade declarada
let results = scanner.scan("<img src=x onerror=alert(1)>");
// [CRITICAL] XSS cross-site scripting detected — offset: 11, pattern: onerror=

// Sinal fraco: o token apenas aparece ⇒ sempre Low, não cruza a linha de rejeição sozinho
let weak = scanner.scan("<script src=\"/app.js\"></script>");
// [LOW] XSS tag present (weak signal) — offset: 0, pattern: <script>
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

# Testes (580: 431 unitários + 148 de integração + 1 teste de documentação)
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
