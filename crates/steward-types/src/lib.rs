/// Shared types, traits, and errors for the Steward agent framework.
///
/// This crate is the foundation that all other Steward crates depend on.
/// It contains:
/// - **Trait contracts** (`traits`) that define module interfaces for parallel development
/// - **Shared data types** (`actions`) used across all subsystems
/// - **Error types** (`errors`) for unified error handling
/// - **Config types** (`config`) for configuration file parsing
pub mod actions;
pub mod config;
pub mod errors;
pub mod traits;

// Re-export commonly used types at the crate root for convenience.
pub use actions::*;
pub use errors::{RateLimitExceeded, StewardError};
pub use traits::*;
