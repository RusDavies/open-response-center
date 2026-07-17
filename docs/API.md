# Operations-Agent API

The operations-agent API is a JSON surface for trusted automation. It is intended for internal
OpenClaw/operations agents, not public reporters.

## Authentication

Create a scoped bearer token for a Django user:

```bash
python manage.py create_operations_agent_token openclaw-agent --user operator --all-scopes
```

The command prints the raw token once. Store that value in the agent runtime secret store. Open Response Center stores
only a SHA-256 hash and a lookup prefix.

Send the token on every request:

```http
Authorization: Bearer rsk_agent_<prefix>_<secret>
Content-Type: application/json
Accept: application/json
```

Available scopes:

- `tickets:create`
- `tickets:read`
- `tickets:message`
- `tickets:update`
- `incidents:promote`

Lifecycle updates and incident promotion also require the token's Django user to be staff/operator.

## Endpoints

### Create Ticket

`POST /api/tickets/` requires `tickets:create`.

```json
{
  "title": "Node upload failure",
  "affected_system": "openclaw-runtime",
  "impact": "high",
  "issue_summary": "Uploads fail after the first screenshot.",
  "reproduction_steps": "1. Open node. 2. Upload screenshots.",
  "expected_outcome": "All screenshots upload.",
  "actual_outcome": "The first upload succeeds, then the node disconnects.",
  "additional_context": "Raised by an operations agent."
}
```

`affected_system` may be a system slug or numeric id, and is filtered through the same visibility
rules as the reporter form.

### Read Ticket

`GET /api/tickets/<id>/` requires `tickets:read`.

Returns the ticket, messages, attachment metadata, and linked operational incidents visible to the
token's user. The serialized ticket includes an `sla` object with overall state, response/resolution
state, due timestamps, completion timestamps, and the active response/resolution windows in minutes.

### Add Message

`POST /api/tickets/<id>/messages/` requires `tickets:message`.

```json
{
  "body": "Checking gateway logs.",
  "is_operator_note": true
}
```

`is_operator_note` is honored only for staff/operator service accounts.

### Update Ticket Lifecycle

`POST /api/tickets/<id>/status/` requires `tickets:update` and a staff/operator service account.

```json
{
  "status": "in_progress",
  "operator": "operator",
  "engineering_reference": "PR-123",
  "note": "Started investigation."
}
```

`operator` may be omitted, a numeric user id, or a username.

Operator status updates and reporter-visible operator replies set the ticket's first-response
timestamp when it has not already been recorded. Moving a ticket to fixed, verified, or closed sets
the resolution timestamp.

### Promote Operational Incident

`POST /api/tickets/<id>/operational-incident/` requires `incidents:promote` and a staff/operator
service account.

```json
{
  "scope": "owned-software",
  "actionability": "auto-fix",
  "access_level": "local-shell",
  "exposure": "private-channel",
  "risk": "medium",
  "p_level": "P3",
  "human_input_required": "no",
  "classification_note": "Automated promotion from an operations agent."
}
```

Promotion is idempotent per ticket/backend: if the ticket already has an OpenClaw workspace incident,
the API returns the existing link instead of creating another incident.
