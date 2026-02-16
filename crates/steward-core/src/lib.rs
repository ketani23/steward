/// Core agent loop for the Steward agent framework.
///
/// Orchestrates the main agent pipeline:
/// - **Agent**: Main loop — receive message, generate actions, execute through security pipeline
/// - **Guardian**: Secondary LLM that reviews every action before execution
/// - **Permissions**: Permission engine with YAML manifest enforcement
/// - **Router**: Intent classification and job routing
/// - **Scheduler**: Parallel job execution with priorities
/// - **Worker**: Job execution with LLM reasoning and tool calls
pub mod agent;
pub mod guardian;
pub mod permissions;
pub mod router;
pub mod scheduler;
pub mod worker;
