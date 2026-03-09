/// Built-in tools — trusted, in-process tool implementations.
///
/// These tools run directly in the agent process without sandboxing.
/// They are audited and trusted by design.
pub mod file_edit;
pub mod file_list;
pub mod file_read;
pub mod file_write;
pub mod memory_search;
pub mod memory_store;
pub mod shell;
pub mod web_fetch;
pub mod web_search;
pub mod workspace;
