use crate::data::{
    CsvInjectionDetector, DeserializationDetector, JwtAttackDetector, MailHeaderDetector,
    PrototypePollutionDetector,
};
use crate::file::{DataLeakDetector, PathTraversalDetector, UploadDetector};
use crate::injection::{
    CommandInjectionDetector, GraphQlInjectionDetector, JndiInjectionDetector,
    LdapInjectionDetector, NoSqlInjectionDetector, SqlInjectionDetector, SsiInjectionDetector,
    SstiDetector, XPathInjectionDetector, XssDetector,
};
use crate::protocol::{
    CorsDetector, DnsRebindingDetector, HeaderInjectionDetector, HostHeaderDetector,
    OpenRedirectDetector, RequestSmugglingDetector, SsrfDetector, WebSocketDetector, XxeDetector,
};
use crate::{Detector, result::DetectionResult};

pub struct Scanner {
    detectors: Vec<Box<dyn Detector>>,
}

impl Default for Scanner {
    fn default() -> Self {
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
}

impl Scanner {
    pub fn new() -> Self {
        Self::default()
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
            if names.contains(&detector.name())
                && let Some(result) = detector.detect(input)
            {
                results.push(result);
            }
        }
        results
    }
}

#[derive(Default)]
pub struct ScannerBuilder {
    detectors: Vec<Box<dyn Detector>>,
}

impl ScannerBuilder {
    pub fn with_detector(mut self, detector: Box<dyn Detector>) -> Self {
        self.detectors.push(detector);
        self
    }

    pub fn build(self) -> Scanner {
        Scanner {
            detectors: self.detectors,
        }
    }
}
