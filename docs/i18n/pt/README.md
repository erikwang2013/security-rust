<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust

**🌐 [中文 (原文)](../../README.md)**

Biblioteca de detecção de ataques escrita em Rust, cobrindo 4 categorias principais — ataques de injeção, ataques de protocolo, ataques de dados/serialização e vazamento de arquivos/dados sensíveis — com um total de 27 detectores. Zero dependência de frameworks externos, varredura pura de strings.

---

## Filosofia de Design

### Por que «detecção» em vez de «bloqueio»

Esta biblioteca se posiciona como um **scanner de entrada puro** — recebe strings e retorna resultados de detecção estruturados. Não está vinculada a nenhum framework web, não faz parsing de requisições/respostas HTTP e não implementa bloqueio em tempo real. Assim, você pode incorporá-la em qualquer pipeline: mecanismos de regras WAF, auditoria de logs, validação prévia em gateways de API, ferramentas CLI de varredura de segurança, etc.

### Princípios de Arquitetura

- **Responsabilidade única** — cada detector cuida de apenas um tipo de ataque e mantém internamente um conjunto de padrões regex pré-compilados
- **Interface unificada** — o trait `Detector` é o único contrato de todos os detectores: `fn detect(&self, input: &str) -> Option<DetectionResult>`
- **Cobertura padrão** — `Scanner::default()` monta todos os 27 detectores com um único comando, utilizável sem configuração
- **Configuração opcional** — `Scanner::builder()` suporta personalização sob demanda, montando detectores seletivamente via `.with_detector()`

### Compensações

| Decisão | Escolha | Motivo |
|------|------|------|
| Regex vs parser | Regex | Em cenários de detecção, a velocidade é prioridade; regex cobre melhor padrões deformados/contornados |
| Primeiro que chegar vs detecção completa | Detecção completa | Uma entrada pode acionar vários tipos de ataque simultaneamente; não se deve deixar de reportar |
| Zero dependências vs adotar serde | Zero dependências | Depende apenas de `regex` + `thiserror`, compilação rápida e tamanho pequeno |

---

## Arquitetura de Design

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

### Responsabilidades dos Módulos

| Módulo | Caminho | Nº de detectores | Responsabilidade |
|------|------|---------|------|
| Núcleo | `src/lib.rs` `result.rs` `scanner.rs` | — | `Detector` trait, `DetectionResult`, `Scanner`/`ScannerBuilder` |
| Injeção | `src/injection/` | 10 | XSS, SQL injection, injeção de comandos, NoSQL, LDAP, XPATH, JNDI, SSI, GraphQL, SSTI |
| Protocolo | `src/protocol/` | 9 | SSRF, XXE, injeção de cabeçalho, ataque de Host header, request smuggling, open redirect, CORS, WebSocket, DNS rebinding |
| Dados | `src/data/` | 5 | Desserialização PHP, injeção de fórmula CSV, injeção de cabeçalho de e-mail, ataques JWT, poluição de protótipo |
| Arquivos | `src/file/` | 3 | Path traversal, upload malicioso de arquivos, vazamento de dados sensíveis |

### Estrutura do Resultado de Detecção

`DetectionResult` retorna estruturadamente os seis campos `attack_type`, `category`, `severity`, `matched_pattern`, `offset`, `message`. Definição completa em [Referência da API](./API.md).

---

## Funcionalidades Implementadas

### Ataques de Injeção (10 detectores)

| Detector | Padrões cobertos | Severidade |
|--------|---------|---------|
| **xss** | `<script>`, manipuladores de eventos como `onerror=`, protocolo pseudo `javascript:`, tags `<svg>`/`<iframe>`, `expression()` de CSS, `eval()`, `document.cookie` | Critical |
| **sql_injection** | `UNION SELECT`, injeção de atraso `sleep()`/`benchmark()`/`pg_sleep()`, enumeração `information_schema`, stored procedures `exec sp_`/`xp_`, padrões de blind boolean `' OR '1'='1`, `LOAD_FILE()`/`INTO OUTFILE` | Critical |
| **command_injection** | Comandos com crase, subcomandos `$()`, execução em cadeia com pipe, reverse shell `/dev/tcp`, funções PHP `passthru()`/`shell_exec()`/`system()`, chamadas `cmd.exe`/`powershell` | Critical |
| **nosql_injection** | Operadores MongoDB `$ne`/`$gt`/`$regex`/`$where`, injeção `$or`, bypass de autenticação `{"$gt": ""}` | Critical |
| **ldap_injection** | Operadores de filtro `(&` `(|` `(!`, enumeração de atributos `*(cn=`, injeção `objectClass`/`uid` | High |
| **xpath_injection** | Bypass booleano `' or '1'='1`, injeção de função `' or true()`, travessia de nós `'] | '` | High |
| **jndi_injection** | `${jndi:ldap://`, ofuscação `${lower:j}`, ofuscação `${upper:j}`, ofuscação de string vazia `${::-j}`, consulta de variáveis de ambiente `${env:}`, propriedades de sistema `${sys:}` | Critical |
| **ssi_injection** | Execução de comandos `<!--#exec cmd=`, inclusão de arquivos `<!--#include file=`, saída de variáveis `<!--#echo var=`, informações de arquivo `<!--#fsize`/`<!--#flastmod` | High |
| **graphql_injection** | Consultas de introspecção `__schema`/`__type`, DoS de aninhamento profundo (≥5 níveis) | Medium |
| **ssti** | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<%=` `<%@`, Velocity `#set()`, escape de sandbox Python MRO `__mro__`/`__subclasses__()` | Critical |

### Ataques de Protocolo e Requisição (9 detectores)

| Detector | Padrões cobertos | Severidade |
|--------|---------|--------|
| **ssrf** | Metadados de nuvem `169.254.169.254`, IPs internos RFC1918 (10.x, 172.16-31.x, 192.168.x), loopback `127.x`, loopback IPv6 `::1`, `0.0.0.0`, protocolos perigosos `gopher://`/`dict://`/`ftp://`/`file://` | Critical |
| **xxe** | Declarações de entidade `<!ENTITY`, referências externas `SYSTEM`/`PUBLIC`, entidades de parâmetro `%`, declarações DTD `<!DOCTYPE` | Critical |
| **header_injection** | CRLF codificado em URL `%0d%0a`, injeção CRLF bruto `\r\n` | High |
| **host_header** | Injeção de múltiplos Host headers, envenenamento `X-Forwarded-Host`/`X-Original-URL`/`X-Rewrite-URL`, Host com CRLF | High |
| **request_smuggling** | Cabeçalhos duplos `Transfer-Encoding`, contrabando `Content-Length: 0`, ofuscação de término chunked `\r\n0\r\n` | High |
| **open_redirect** | URLs relativas de protocolo `//evil.com`, redirecionamento por protocolos pseudo `javascript:`/`data:text/html` | Medium |
| **cors** | Bypass `Origin: null`, combinação `Access-Control-Allow-Origin: *` + Credentials | Medium |
| **websocket** | Handshake `Upgrade: websocket`, WS entre origens `Origin: null`, conexão em texto puro `ws://` | High |
| **dns_rebinding** | Host header com IPs internos `127.x`/`10.x`/`192.168.x`/`172.16-31.x`, `localhost`, `::1`, `0.0.0.0` | High |

### Ataques de Dados e Serialização (5 detectores)

| Detector | Padrões cobertos | Severidade |
|--------|---------|--------|
| **deserialization** | Objetos serializados PHP `O:número:`/`C:número:`, arrays `a:número:{`, chamadas `unserialize()`, métodos mágicos `__wakeup`/`__destruct`/`__toString` | Critical |
| **csv_injection** | Caracteres de fórmula no início da linha `=`/`+`/`-`/`@`, troca dinâmica de dados DDE, pipe de comandos `cmd|`, funções `@SUM()` | Medium |
| **mail_header** | Injeção Bcc:`/`Cc:` cópia oculta, múltiplos remetentes `From:`, injeção de cabeçalhos MIME `MIME-Version:`/`Content-Type: multipart`, manipulação de limite `boundary=` | Medium |
| **jwt_attack** | Bypass de algoritmo vazio `alg: none`, injeção de path traversal `kid`, segmento de assinatura vazio, segmento de payload vazio | High |
| **prototype_pollution** | Poluição da cadeia de protótipos `__proto__`/`constructor.prototype`, sequestro de propriedades `__defineGetter__`/`__defineSetter__`/`__lookupGetter__`/`__lookupSetter__` | High |

### Arquivos e Dados Sensíveis (3 detectores)

| Detector | Padrões cobertos | Severidade |
|--------|---------|--------|
| **path_traversal** | Travessia de diretórios `../`/`..\\`, bypass de codificação URL `%2e%2e`, wrappers de protocolo `php://filter`/`php://input`/`phar://`/`zip://`/`data://`/`expect://`/`glob://`, truncamento por byte nulo `%00` | Critical |
| **upload** | Tags PHP `<?php`/`<?=`, tags ASP `<%@`/`<%=`, padrões de backdoor `eval($_`/`system($_`/`exec($_`/`passthru($_`, superglobais `$_GET`/`$_POST`/`$_REQUEST`/`$_SERVER`, bypass de codificação `base64_decode()` | Critical |
| **data_leak** | PAN de cartão de crédito com 16 dígitos (Visa/MasterCard/AmEx/Discover/JCB/Diners), AWS Access Key `AKIA...`, cabeçalho de chave privada PEM `-----BEGIN`, chaves de API OpenAI/LLM `sk-...`, strings de conexão de banco `mongodb://`/`mysql://`/`postgresql://`/`redis://`/`jdbc:`, Token JWT | Critical |

---

## Como Usar

Utilizável sem configuração:

```rust
use security_rust::Scanner;

let scanner = Scanner::default();
let results = scanner.scan("<script>alert('xss')</script>");
// [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
```

Referência completa da API (instalação, varredura seletiva, configuração personalizada, exibição de severidade, desempenho) em [Referência da API](./API.md).

---

## Desenvolvimento

```bash
# Compilar
cargo build --release

# Testar (46 testes de integração)
cargo test

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
