Read docs/architecture.md section 10 (Communication Layer).
Read crates/steward-types/src/traits.rs for ChannelAdapter.

Implement the WhatsApp adapter in crates/steward-channels/src/whatsapp.rs
and the approval UX in crates/steward-channels/src/confirmation.rs.

Requirements:
- Implement ChannelAdapter trait for WhatsApp
- Use WhatsApp Business Cloud API (HTTP API — not Baileys/websocket for v1)
- Inbound: webhook endpoint (axum HTTP server) that receives WhatsApp webhook events,
  verifies webhook signature, parses message payloads
- send_message(): POST to WhatsApp Business API to send text messages
- request_approval(): send a structured approval message with the action details
  and interactive buttons (Approve / Reject). Wait for button callback response
  with configurable timeout.
- Webhook signature verification using HMAC-SHA256
- Handle WhatsApp message types: text, image (extract URL), document (extract URL)
- Rate limiting: respect WhatsApp's messaging rate limits
- Include the axum webhook router as a separate function that can be mounted
  into a larger web server

Write tests:
- Test webhook signature verification (valid and invalid)
- Test message parsing for different WhatsApp payload types
- Test approval flow (mock the webhook callback)
- Test timeout on approval (no response within window)
- Test rate limiting

When done:
- Run `cargo fmt --all`
- Run `cargo clippy --all-targets --all-features -- -D warnings` and fix any warnings
- Run `cargo test -p steward-channels` and ensure all tests pass
- Stage and commit: `git add -A && git commit -m "feat(channels): implement WhatsApp channel adapter with webhook verification and approval flow"`
- Push and create PR: `git push origin HEAD && gh pr create --title "feat(channels): implement WhatsApp channel adapter" --body "Implements ChannelAdapter trait for WhatsApp Business Cloud API with webhook signature verification, message parsing, approval flow with interactive buttons, and rate limiting." --base main`
