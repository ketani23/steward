Read docs/architecture.md section 11 (Model Support).
Read crates/steward-types/src/traits.rs for the LlmProvider trait.

Implement LLM providers in crates/steward-core/src/llm/.

Requirements:
- Create an llm/ module directory with mod.rs, anthropic.rs, ollama.rs
- Update crates/steward-core/src/lib.rs to declare the llm module
- Both implement the LlmProvider trait from steward-types
- AnthropicProvider: HTTP client to the Anthropic Messages API
  - Supports Claude Opus, Sonnet, Haiku (use the latest model IDs: claude-opus-4-6, claude-sonnet-4-5-20250929, claude-haiku-4-5-20251001)
  - Handles tool_use responses (tool calls in assistant response)
  - Streaming support (optional, mark as TODO if complex)
  - API key accepted as a constructor parameter (String)
  - Respect rate limits from response headers
- OllamaProvider: HTTP client to the Ollama API
  - Supports any model available in the local Ollama instance
  - Convert between Ollama's chat format and Steward's CompletionRequest/Response
  - Tool calling via Ollama's function calling support
- Both providers must serialize/deserialize tool definitions to/from
  the provider's expected format
- Include a ProviderRouter that selects provider based on config
  (primary provider, fallback chain)

Write tests:
- Test request serialization for both providers
- Test response deserialization (including tool_use blocks)
- Test error handling (rate limit, auth failure, timeout)
- Test provider routing (primary → fallback on failure)
- Use mock HTTP server (wiremock or similar) — do NOT call real APIs in tests

When done:
- Run `cargo fmt --all`
- Run `cargo clippy --all-targets --all-features -- -D warnings` and fix any warnings
- Run `cargo test -p steward-core` and ensure all tests pass
- Stage and commit: `git add -A && git commit -m "feat(core): implement LLM providers for Anthropic and Ollama with provider routing"`
- Push and create PR: `git push origin HEAD && gh pr create --title "feat(core): implement LLM providers" --body "Implements LlmProvider trait for Anthropic Messages API and Ollama API with tool calling support, rate limit handling, and provider routing with fallback chain." --base main`
