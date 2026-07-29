// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

pub mod cors;
pub mod dns_rebinding;
pub mod header_injection;
pub mod host_header;
pub mod open_redirect;
pub mod request_smuggling;
pub mod ssrf;
pub mod websocket;
pub mod xxe;

pub use cors::CorsDetector;
pub use dns_rebinding::DnsRebindingDetector;
pub use header_injection::HeaderInjectionDetector;
pub use host_header::HostHeaderDetector;
pub use open_redirect::OpenRedirectDetector;
pub use request_smuggling::RequestSmugglingDetector;
pub use ssrf::SsrfDetector;
pub use websocket::WebSocketDetector;
pub use xxe::XxeDetector;
