pub mod csv_injection;
pub mod deserialization;
pub mod jwt_attack;
pub mod mail_header;
pub mod prototype_pollution;

pub use csv_injection::CsvInjectionDetector;
pub use deserialization::DeserializationDetector;
pub use jwt_attack::JwtAttackDetector;
pub use mail_header::MailHeaderDetector;
pub use prototype_pollution::PrototypePollutionDetector;
