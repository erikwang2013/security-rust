use crate::data::{CsvInjectionDetector, DeserializationDetector, JwtAttackDetector, MailHeaderDetector, PrototypePollutionDetector};
use crate::file::{DataLeakDetector, PathTraversalDetector, UploadDetector};
use crate::injection::{CommandInjectionDetector, GraphQlInjectionDetector, JndiInjectionDetector, LdapInjectionDetector, NoSqlInjectionDetector, SqlInjectionDetector, SsiInjectionDetector, SstiDetector, XPathInjectionDetector, XssDetector};
use crate::protocol::{CorsDetector, DnsRebindingDetector, HeaderInjectionDetector, HostHeaderDetector, OpenRedirectDetector, RequestSmugglingDetector, SsrfDetector, WebSocketDetector, XxeDetector};
use crate::{result::DetectionResult, Detector};

pub struct Scanner {
    detectors: Vec<Box<dyn Detector>>,
}

impl Scanner {
    pub fn default() -> Self {
        Self {
            detectors: vec![
                // Injection
                Box::new(XssDetector),
                Box::new(SqlInjectionDetector),
                Box::new(CommandInjectionDetector),
                Box::new(NoSqlInjectionDetector),
                Box::new(LdapInjectionDetector),
                Box::new(XPathInjectionDetector),
                Box::new(JndiInjectionDetector),
                Box::new(SsiInjectionDetector),
                Box::new(GraphQlInjectionDetector),
                Box::new(SstiDetector),
                // Protocol
                Box::new(SsrfDetector),
                Box::new(XxeDetector),
                Box::new(HeaderInjectionDetector),
                Box::new(HostHeaderDetector),
                Box::new(RequestSmugglingDetector),
                Box::new(OpenRedirectDetector),
                Box::new(CorsDetector),
                Box::new(WebSocketDetector),
                Box::new(DnsRebindingDetector),
                // Data
                Box::new(DeserializationDetector),
                Box::new(CsvInjectionDetector),
                Box::new(MailHeaderDetector),
                Box::new(JwtAttackDetector),
                Box::new(PrototypePollutionDetector),
                // File
                Box::new(PathTraversalDetector),
                Box::new(UploadDetector),
                Box::new(DataLeakDetector),
            ],
        }
    }

    pub fn builder() -> ScannerBuilder {
        ScannerBuilder::default()
    }

    pub fn scan(&self, input: &str) -> Vec<DetectionResult> {
        let mut results = Vec::new();
        for detector in &self.detectors {
            if let Some(result) = detector.detect(input) {
                results.push(result);
            }
        }
        results
    }

    pub fn scan_with(&self, input: &str, names: &[&str]) -> Vec<DetectionResult> {
        let mut results = Vec::new();
        for detector in &self.detectors {
            if names.contains(&detector.name()) {
                if let Some(result) = detector.detect(input) {
                    results.push(result);
                }
            }
        }
        results
    }
}

#[derive(Default)]
pub struct ScannerBuilder {
    detectors: Vec<Box<dyn Detector>>,
    #[allow(dead_code)]
    allowed_methods: Vec<String>,
    #[allow(dead_code)]
    max_body_size: usize,
    #[allow(dead_code)]
    allowed_content_types: Vec<String>,
    #[allow(dead_code)]
    csrf_origins: Vec<String>,
    #[allow(dead_code)]
    ip_ban_threshold: u32,
    #[allow(dead_code)]
    ip_ban_window_secs: u64,
    #[allow(dead_code)]
    ip_ban_duration_secs: u64,
    #[allow(dead_code)]
    allowed_extensions: Vec<String>,
}

impl ScannerBuilder {
    pub fn with_detector(mut self, detector: Box<dyn Detector>) -> Self {
        self.detectors.push(detector);
        self
    }

    pub fn allowed_methods(mut self, methods: &[&str]) -> Self {
        self.allowed_methods = methods.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn max_body_size(mut self, size: usize) -> Self {
        self.max_body_size = size;
        self
    }

    pub fn allowed_content_types(mut self, types: &[&str]) -> Self {
        self.allowed_content_types = types.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn csrf_origins(mut self, origins: &[&str]) -> Self {
        self.csrf_origins = origins.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn ip_ban_threshold(mut self, threshold: u32) -> Self {
        self.ip_ban_threshold = threshold;
        self
    }

    pub fn ip_ban_window_secs(mut self, window: u64) -> Self {
        self.ip_ban_window_secs = window;
        self
    }

    pub fn ip_ban_duration_secs(mut self, duration: u64) -> Self {
        self.ip_ban_duration_secs = duration;
        self
    }

    pub fn allowed_extensions(mut self, extensions: &[&str]) -> Self {
        self.allowed_extensions = extensions.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn build(self) -> Scanner {
        Scanner {
            detectors: self.detectors,
        }
    }
}
