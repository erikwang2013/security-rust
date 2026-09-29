// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity, regex_detect};
use regex::Regex;
use std::sync::LazyLock;

/// 强信号：形态本身只能来自攻击 —— 关键字出现在**语句位置**、或带着 SQL 实参。
/// 判据是「形态」而不是「词出现」：`sleep(` 只有当它处在行首/引号/`)`/`;`/布尔关键字之后
/// 才是注入，因为注入总是**追加**在原值上；`time.sleep(2)`、`retrying after sleep(2)`、
/// `Add a sleep(1) between retries` 都不在那个位置。
/// 17 条分支合并成 1 条 alternation —— `regex_detect` 对列表里每条 `Regex` 各跑一次
/// `find`，干净输入下 17 次全文扫描变 1 次。分支顺序 = 原 vec 顺序（同一位置上取最左
/// 分支；与「按列表顺序取第一条命中的模式」相比偏移量可能不同，档位不变）。
/// 各分支共同的 `(?i)` 提升为外层 `(?i:…)`，作用域正好覆盖全部 17 条分支。
static STRONG_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        // `[\s+]|%20`: `+` 与 `%20` 都是空格的 URL 编码；`/**/` 可切开关键字（UN/**/ION）
        r"(?i:UN(?:/\*.*?\*/)?ION(?:[\s+]|%20)+(?:ALL(?:[\s+]|%20)+)?SELECT",
        // 选择列表必须像 SQL（标识符/`*`/函数调用），否则英文散文 `select … from …` 全是误报
        r#"|SELECT(?:[\s+]|%20)+(?:DISTINCT(?:[\s+]|%20)+)?(?:\*|[\w"'\[\].]+(?:\([^)\n]{0,40}\))?(?:\s*,\s*[\w"'\[\].]+(?:\([^)\n]{0,40}\))?)*)(?:[\s+]|%20)+FROM(?:[\s+]|%20)+[\w"\[\].]+"#,
        // `/*!` 版本注释包着 SQL 语句时才是注入；Doxygen 的 `/*! \brief … */` 不是
        r"|/\*!\d*\s*(?:union|select|insert|update|delete|drop|alter|sleep|benchmark|load_file|outfile|or|and|where)\b",
        // 语句位置（见上）+ 可选的 URL 编码空格
        r#"|(?:^|['"();]|\b(?:and|or|select|union|where|having)\b)[\s+]*sleep\s*\("#,
        // BENCHMARK 的签名是 `(次数, 表达式)`：`benchmark(fn, { iterations: 10000 })` 不命中
        r"|benchmark\s*\(\s*\d+\s*,",
        // 同 `sleep(`：`Call pg_sleep(5) to pause the session` 与 PG 报错里的
        // `function pg_sleep(integer) does not exist` 都在语句位置之外
        r#"|(?:^|['"();]|\b(?:and|or|select|union|where|having)\b)[\s+]*pg_sleep\s*\("#,
        // 文档里写 `exec sp_who2 lists active sessions` / `call exec xp_cmdshell` 时
        // `exec` 前面是普通英文词；注入里它是栈式查询，前面是 `;` 或引号
        r#"|(?:^|['"();])\s*exec\s+(?:sp_|xp_)"#,
        // 必须带时间字面量：`use WAITFOR DELAY to pause before the retry` 不带
        r#"|WAITFOR\s+DELAY\s+['"]?\d"#,
        r"|'\s*OR\s*'1'\s*=\s*'1",
        r"|'\s*OR\s*1\s*=\s*1\s*--",
        // 只认带引号 / 十六进制实参的读取：`load_file(fd)`、`LOAD_FILE()` 是普通函数调用
        r#"|LOAD_FILE\s*\(\s*(?:['"]|0x)"#,
        // `INTO OUTFILE` 在真实语法里**必须**跟一个带引号的路径；SQL 教程里那句
        // `Use INTO OUTFILE to export the result set to disk` 不跟引号（`/**/` 变体由下一条兜底）
        r#"|INTO\s+(?:OUT|DUMP)FILE\s+['"]"#,
        // MySQL 这里必须跟一个带引号的路径：`The outfile is written to the shared drive` 不命中
        r#"|OUTFILE\s+['"]"#,
        // 左上下文不收 `'` / `"`：栈式注入**必须**有 `;`，而引号后的 DDL/DML 是语法错误、
        // 打不出注入。收进去反而命中每一条回显失败语句的日志 ——
        // `ERROR 1064: ... near 'INSERT INTO users (id) VALUES (1)'`、
        // `{"query": "INSERT INTO users VALUES (1)"}`、`[INFO] sql="DROP TABLE tmp"`
        r#"|(?:^|[();])\s*DROP\s+TABLE"#,
        r#"|(?:^|[();])\s*INSERT\s+INTO"#,
        // 注释符必须**紧贴**那个引号，且只认单引号：`"`/`)` 后面隔一段空白再接注释符的
        // 形态在正常代码里遍地都是 —— Rust 原始字符串终止符 `r#"…"#`（`"#).unwrap(),`）、
        // C 的 `f(a, b) /* note */`、Velocity 的 `)` 换行 `#foreach`、shell 的
        // `grep 'x' -- file` 全被判 Critical（本仓库自己的源码就有十几处）。
        // `--` 仍要求其后是空白/行尾/`+`（MySQL 的 URL 编码空格），SSI 的 `"-->` 不受影响。
        r#"|(?:'\)?#[^"'\n]*(?:\n|$)|'\)[ \t]*--(?:\s|$|\+)|'--(?:\s|$|\+)|'/\*|\)[ \t]*--(?:\s|$|\+))"#,
        // 注释后的布尔关键字必须带 SQL 操作数：Markdown 的 `# Or use the CLI`、
        // 散文里的 `-- and the conclusions` 都不带
        r#"|(?:/\*.*?\*/|--|#)\s*(?:or\s+['"(\d]|and\s+['"(\d]|union\s+(?:all\s+)?select\b|select\s+(?:\*|['"(\d]|[\w`\[\]]+\s*(?:,|from\b))))"#,
    ))
    .unwrap()
});

/// 弱信号：词一出现就命中，但形态与「文档在讨论数据库」逐字节同形。
/// `information_schema` 在 PG 报错日志、SQL 教程里都正常出现；而它真正的攻击形态
/// （`UNION SELECT … FROM information_schema`、`SELECT … FROM information_schema`）
/// 已由强档的两条覆盖。所以报 Low：仍然检出（不静默漏报），单条 5 分不触发拒绝，
/// 是否升级交给调用方按聚合分决定。
/// 只有 1 条分支，仍收成单个 `Regex` 与强档同型 —— 调用点用
/// `std::slice::from_ref` 包成单元素切片，少一层 `Vec` 间接。
static WEAK_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i:information_schema)")
    .unwrap()
});

pub struct SqlInjectionDetector;

impl Detector for SqlInjectionDetector {
    fn name(&self) -> &'static str {
        "sql_injection"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(
            std::slice::from_ref(&*STRONG_PATTERNS),
            self.name(),
            AttackCategory::Injection,
            Severity::Critical,
            "SQL injection detected",
            input,
        )
        .or_else(|| {
            regex_detect(
                std::slice::from_ref(&*WEAK_PATTERNS),
                self.name(),
                AttackCategory::Injection,
                Severity::Low,
                "SQL keyword present (weak signal)",
                input,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det() -> SqlInjectionDetector {
        SqlInjectionDetector
    }

    fn assert_hit(input: &str) {
        assert_hit_at(input, Severity::Critical);
    }

    fn assert_hit_at(input: &str, severity: Severity) {
        crate::test_helpers::assert_detected(&det(), input, AttackCategory::Injection, severity);
    }

    #[test]
    fn name_is_sql_injection() {
        assert_eq!(det().name(), "sql_injection");
    }

    #[test]
    fn detects_common_payloads() {
        for input in [
            "1 UNION SELECT password FROM users",
            "1; SELECT pg_sleep(5)",
            "admin' OR '1'='1",
            "SELECT * FROM users WHERE id=1",
            "id=1 /*!50000union select*/",
            "1; WAITFOR DELAY '0:0:5'",
            "username' OR 1=1 --",
            "admin'--",
            "1') --",
            "x'#comment",
            "x'#comment&foo=bar",
            "-- or 1=1",
            "/*x*/ union select",
            // `+` / `%20` 是空格的 URL 编码
            "1+UNION+SELECT+username,password+FROM+users",
            "1%20UNION%20SELECT%201",
            "SELECT+id+FROM+users",
            // `/**/` 切开关键字
            "UN/**/ION SELECT 1,2,3",
            // 选择列表
            "SELECT name, email FROM users",
            "SELECT COUNT(*) FROM users",
            "SELECT 用户名 FROM 用户表",
            "SELECT DISTINCT id FROM t",
            "SELECT id, count(*) FROM logs",
            "a'/**/or 1=1",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn benign_inputs_not_detected() {
        for input in [
            "Hello, this is a normal text input. Nothing suspicious here.",
            "Please choose an option below",
            "I will sleep well tonight",
            "The benchmark results look great",
            "Drop me a line when you arrive",
            "The information desk is on the second floor",
            "q=2024--2025",
            "q=donation=5",
            "穿越之霸道总裁爱上我--重生之都市修仙",
            "chapter 2024--2025 更新",
            "donation=5&q=test",
        ] {
            assert!(det().detect(input).is_none(), "false positive: {input}");
        }
    }

    /// 真实世界的干净输入：散文、HTML、URL、JSON、日志。
    /// 上面 `benign_inputs_not_detected` 是人工构造的近失配（`select from users` 测的是
    /// “没有空格”），挡不住真正的误报 —— `href="#"` 与英文 `select … from …` 就是这样漏出去的。
    #[test]
    fn realistic_text_not_detected() {
        for input in [
            // HTML：`#` 是属性值，不是 MySQL 行注释
            r##"<a href="#">Back to top</a>"##,
            "<a href='#'>",
            "See the anchor href=\"#\" for details.",
            r##"<a href="#main">Skip to content</a>"##,
            r##"<a href="#section-2">Jump</a>"##,
            r##"<p>Read the <a href="#faq">FAQ</a> before contacting support.</p>"##,
            r##"<a href="/about">About us</a>"##,
            r##"<link rel="stylesheet" href="/static/app.css?v=3">"##,
            r##"<div id="top">"##,
            "color: #09f; background: #fff;",
            // 英文散文里的 select … from …
            "Please select a date from the calendar below.",
            "Select your language from the menu.",
            "select the file from your computer",
            "I will select the best option from these.",
            "Please select the country from the dropdown list above.",
            "We will select the winner from all entries on Friday.",
            "Please describe the issue, then select a priority from the list.",
            "Veuillez sélectionner votre langue dans le menu.",
            "Our team will respond to your request within 24 hours.",
            // URL 与 JSON
            "https://docs.example.com/guide#getting-started",
            "https://shop.example.com/products?color=%23ff0000&sort=price_asc",
            "http://example.com/search?q=best+laptop+2026&page=2",
            r##"{"theme":"dark","accent":"#fff","bg":"#1a1a1a"}"##,
            r##"{"build":{"target":"x86_64","profile":"release","features":[]}}"##,
            // 日志
            "2026-09-30T12:00:00Z INFO  request completed status=200 path=/api/v1/items duration=42ms",
            "level=error msg=\"disk usage at 91%\" service=ingest host=node-7",
            // 杂项：`#` 的字面用法、加号、引号
            "The # symbol is also known as a hash or pound sign.",
            "Contact us at support@example.com or call +1-555-0100.",
        ] {
            assert!(det().detect(input).is_none(), "false positive: {input}");
        }
    }

    /// 收紧过的模式必须**双向**钉住：上半段是「收紧不能丢检出」，下半段是
    /// 「放宽不能放任误报」。每条正常内容都是真实形态 —— 代码、日志、散文、文档，
    /// 不是合成的近失配。
    #[test]
    fn tightened_shapes_detect_attacks_and_ignore_ordinary_text() {
        // `sleep(`：语句位置才是注入（注入是追加到原值上的）
        assert_hit("1 AND SLEEP(5)");
        assert_hit("1 OR SLEEP(5)");
        assert_hit("1; SELECT SLEEP(5)");
        assert_hit("1' AND SLEEP(5)-- ");
        // `BENCHMARK(次数, 表达式)` 是 MySQL 的签名
        assert_hit("1 AND BENCHMARK(1000000,MD5(1))");
        // `pg_sleep(` / `exec sp_` / `WAITFOR DELAY`：同为语句位置判据
        assert_hit("1 AND pg_sleep(5)");
        assert_hit("1; EXEC xp_cmdshell 'dir'");
        assert_hit("1; EXEC sp_executesql N'SELECT 1'");
        assert_hit("1' EXEC xp_cmdshell 'dir'");
        assert_hit("1; WAITFOR DELAY '0:0:5'");
        assert_hit("1; WAITFOR DELAY 0:0:5");
        // `/*!` 版本注释包着 SQL 语句
        assert_hit("1 AND /*!50000SLEEP(5)*/");
        // 带引号 / 十六进制实参的文件读取
        assert_hit("1 UNION SELECT LOAD_FILE('/etc/passwd')");
        assert_hit("1 UNION SELECT LOAD_FILE(0x2f657463)");
        assert_hit("1 UNION SELECT 'x' INTO OUTFILE '/tmp/a'");
        assert_hit("1 UNION SELECT 'x' INTO DUMPFILE '/tmp/a'");
        assert_hit("1 UNION SELECT 'x' INTO/**/OUTFILE '/tmp/a'");
        // 语句位置的 DDL/DML
        assert_hit("1; DROP TABLE users");
        assert_hit("1; INSERT INTO users VALUES(1)");
        assert_hit("1'; DROP TABLE users");
        assert_hit("1'; INSERT INTO users VALUES(1)");
        // 注释后的布尔关键字带 SQL 操作数
        assert_hit("-- or 1=1");
        assert_hit("# or 1=1");
        assert_hit("/*x*/ union select");

        for input in [
            // `time.sleep` / 重试退避 / 日志里的耗时说明
            "Add a sleep(1) between retries to avoid hammering upstream.",
            "2026-09-30T12:00:01Z WARN retrying after sleep(2)",
            "        except TransientError:\n            sleep(2 ** i)",
            "time.sleep(0.5)  # backoff",
            // 基准测试调用：第一个实参是函数，不是次数
            "benchmark(parseConfig, { iterations: 10000 });",
            // Doxygen 的 `/*!` 注释
            "/*! Parses the config. */\nint parse(const char *p);",
            // 普通函数调用与文档里提到的函数名
            "The <code>load_file(fd)</code> helper reads a descriptor.",
            "MySQL's <code>LOAD_FILE()</code> needs the FILE privilege.",
            "The outfile is written to the shared drive every night.",
            "Please insert into the form the reference number shown above.",
            "Then drop table 12 for the party at the venue.",
            // 文档在**讲解**这些函数：函数名前面是普通英文词，不是语句位置
            "Call pg_sleep(5) to pause the session during a migration.",
            "ERROR: function pg_sleep(integer) does not exist",
            "The stored procedure exec sp_who2 lists active sessions.",
            "Legacy jobs call exec xp_cmdshell, which is disabled by default.",
            "In T-SQL use WAITFOR DELAY to pause before the retry.",
            "Use INTO OUTFILE to export the result set to disk.",
            "INTO DUMPFILE writes a single row without delimiters.",
            // 日志回显失败语句：引号后面跟 DDL/DML 是**被记录的文本**，不是栈式注入
            "ERROR 1064: You have an error in your SQL syntax near 'INSERT INTO users (id) VALUES (1)' at line 1",
            "ERROR 1051: Unknown table 'users' near 'DROP TABLE users_old' at line 1",
            r#"{"query": "INSERT INTO users VALUES (1)"}"#,
            r#"[INFO] sql="DROP TABLE tmp_users""#,
            // Markdown 标题、破折号散文、CSS 注释：注释后跟的是普通英文词
            "# Or use the CLI instead.",
            "## And then run the tests.",
            "The results -- and the conclusions -- were surprising.",
            "Wait -- or restart the service.",
            "/* reset */ and then apply the theme",
        ] {
            crate::test_helpers::assert_clean(&det(), input);
        }
    }

    /// 收紧后的注释符模式：只认**紧贴单引号**的 `--` / `#` / `/*`（`#` 后可跨一个 `)`）。
    /// 旧写法允许 `"` 或裸 `)` 之后隔任意空白再接注释符，于是 Rust 原始字符串终止符
    /// `r#"…"#`、C 的 `f(a, b) /* note */`、Velocity 的 `)` 换行 `#foreach` 全部命中
    /// Critical —— 单是本仓库自己的源码就有十几处。
    #[test]
    fn quote_comment_lookalikes_are_not_injection() {
        // 攻击方向：注释符紧贴单引号，仍是 Critical
        for input in [
            "admin'--",
            "1') --",
            "1) --",
            "x'#comment",
            "x'#comment&foo=bar",
            "1')#x",
            "a'/**/or 1=1",
            "username' OR 1=1 --",
        ] {
            assert_hit(input);
        }
        // 正常代码方向：注释符前面不是单引号
        for input in [
            // Rust 原始字符串终止符 —— 本仓库 src/ 里十几处
            r##"let re = Regex::new(r#"\d+"#).unwrap(),"##,
            "static P: LazyLock<Vec<Regex>> = LazyLock::new(|| vec![Regex::new(r\"#x\").unwrap()]);",
            // C / JS 块注释，以及括号后的自减
            "int r = compute(a, b) /* note: keep in sync */;",
            "if (n) --i;",
            // Velocity：`)` 换行 `#foreach`（`#` 前是换行，不是引号）
            "#set($x = 5)\n#foreach($item in $items)",
            // shell / CLI 里的 `#` 与 `--`
            "echo 'hello' # say hi",
            "grep 'pattern' -- file.txt",
            "git commit -m 'msg' -- file.txt",
            // 单引号字符串里的 `/*`，但不是紧贴注释符
            "x = 'a' /* c */",
        ] {
            crate::test_helpers::assert_clean(&det(), input);
        }
    }

    /// 降档：`information_schema` 是「词出现」型信号，PG 报错日志与 SQL 教程里都正常
    /// 出现，而它真正的注入形态（`UNION SELECT … FROM`、`SELECT … FROM`）由强档覆盖。
    /// 所以仍检出（不静默漏报），但只报 Low，单条不触发调用方的拒绝线。
    #[test]
    fn information_schema_is_low_not_critical() {
        for input in [
            "ERROR query failed: relation \"information_schema\" does not exist",
            "Read <code>information_schema.tables</code> to list tables.",
        ] {
            assert_hit_at(input, Severity::Low);
        }
        // 降档的是「词」，不是注入本身
        for input in [
            "1 UNION SELECT table_name FROM information_schema.tables",
            "1 AND (SELECT 1 FROM information_schema.tables)",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn edge_cases() {
        assert!(det().detect("").is_none());
        assert!(det().detect(" \t\n ").is_none());
        assert!(det().detect("你好世界 こんにちは").is_none());
        // near misses: keyword present but not the payload form
        assert!(det().detect("UNOIN SILE CT *").is_none());
        assert!(det().detect("select from users").is_none());
        assert!(det().detect("sleep 5").is_none());
    }

    #[test]
    fn obfuscated_variants_detected() {
        for input in [
            "1 UnIoN SeLeCt password",
            "Sleep(5)",
            "1; SELECT Pg_Sleep(10)",
            "' or '1'='1",
        ] {
            assert_hit(input);
        }
    }
}
