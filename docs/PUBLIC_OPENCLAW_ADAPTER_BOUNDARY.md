# Public OpenClaw Adapter Boundary

The public open-core repository may include a sanitized OpenClaw adapter as an optional reference
integration.

## Public Scope

The public adapter may include:

- The ticket-to-incident promotion flow.
- Adapter interfaces for creating incidents, syncing status, adding comments, and attaching
  evidence.
- Configuration examples using placeholder paths and environment variables.
- Tests that use temporary directories or fixtures instead of a real private workspace.
- Documentation that explains the integration as one possible incident backend.

## Private Scope

The public adapter must not include:

- Private workspace paths, chat platform channel IDs, hostnames, usernames, or project mappings.
- private agent/OpenClaw operating instructions or agent workflow notes.
- Real incident data, ticket data, uploaded evidence, or local database content.
- Assumptions that the reader has access to any private OpenClaw workspace.
- Any credentials, tokens, webhook URLs, or gateway details.

## Product Boundary

Open Response Center should treat OpenClaw as an incident backend behind an adapter interface, not as
the product-domain source of truth. The public app should remain useful with a stub, demo, or future
native incident backend even when OpenClaw is not available.
