// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

pub mod csv_injection;
pub mod deserialization;
pub mod formula_injection;
pub mod jwt_attack;
pub mod mail_header;
pub mod prototype_pollution;
pub mod redos;

pub use csv_injection::CsvInjectionDetector;
pub use deserialization::DeserializationDetector;
pub use formula_injection::FormulaInjectionDetector;
pub use jwt_attack::JwtAttackDetector;
pub use mail_header::MailHeaderDetector;
pub use prototype_pollution::PrototypePollutionDetector;
pub use redos::ReDoSDetector;
