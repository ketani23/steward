/// Memory subsystem for the Steward agent framework.
///
/// PostgreSQL + pgvector backed persistent memory with:
/// - **Workspace**: Core memory storage with provenance tracking
/// - **Search**: Hybrid full-text + vector search with RRF fusion
/// - **Provenance**: Memory origin tracking and trust scoring
/// - **Integrity**: Periodic audit for memory poisoning detection
pub mod integrity;
pub mod provenance;
pub mod search;
pub mod workspace;
