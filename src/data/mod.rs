pub mod deserialization;
pub mod csv_injection;
pub mod mail_header;
pub mod jwt_attack;
pub mod prototype_pollution;

pub use deserialization::DeserializationDetector;
pub use csv_injection::CsvInjectionDetector;
pub use mail_header::MailHeaderDetector;
pub use jwt_attack::JwtAttackDetector;
pub use prototype_pollution::PrototypePollutionDetector;
