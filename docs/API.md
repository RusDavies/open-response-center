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
Authorization: Bearer orc_agent_<prefix>_<secret>
Content-Type: application/json
Accept: application/json
```

Available scopes:

- `tickets:create`
- `tickets:read`
- `tickets:message`
- `tickets:update`
- `cases:create`
- `cases:read`
- `cases:update`
- `cases:note`
- `cases:event`
- `incidents:promote`

Lifecycle updates and incident promotion also require the token's Django user to be staff/operator.

## Endpoints

### Create or Upsert Case

`POST /api/v1/cases/` requires `cases:create`.

This is the preferred integration surface for automation that has its own event or case identifier.
`external_reference.provider` and `external_reference.external_id` are idempotency keys: repeat them
to update the same Open Response Center case instead of creating duplicates.

```json
{
  "external_reference": {
    "provider": "openclaw-gateway-watchdog",
    "external_id": "gateway-health-152956",
    "metadata": {
      "gateway": "primary",
      "check": "heartbeat"
    }
  },
  "title": "Gateway heartbeat failed",
  "affected_system": "openclaw-runtime",
  "impact": "high",
  "status": "in_progress",
  "issue_summary": "Gateway watchdog missed two heartbeats.",
  "reproduction_steps": "1. Poll gateway health. 2. Observe missed heartbeat.",
  "expected_outcome": "Gateway responds before the watchdog deadline.",
  "actual_outcome": "Gateway did not respond before the deadline.",
  "additional_context": "Raised by the watchdog handoff API.",
  "note": "Watchdog handoff moved the case into investigation."
}
```

The first request returns `201` with `"created": true`. Later requests with the same provider/external
ID return `200` with `"created": false` and update the existing case fields supplied in the payload.
Supplying `status` requires a staff/operator service account and records the normal lifecycle event.

### Read Case

`GET /api/v1/cases/<id>/` requires `cases:read`.

The response contains the serialized ticket lifecycle, SLA state, workflow checklist, messages,
attachment metadata, linked operational incidents, external references, and structured case events:

```json
{
  "case": {
    "ticket": {
      "id": 42,
      "status": "in_progress",
      "sla": {}
    },
    "external_references": [
      {
        "provider": "openclaw-gateway-watchdog",
        "external_id": "gateway-health-152956",
        "metadata": {
          "gateway": "primary"
        }
      }
    ],
    "messages": [],
    "attachments": [],
    "operational_incidents": [],
    "case_events": []
  }
}
```

### Update Case

`PATCH /api/v1/cases/<id>/` requires `cases:update`.

Use this for direct case updates when the caller already knows the Open Response Center case ID.
Supported fields match the upsert endpoint's mutable fields, including `title`, `impact`, structured
ticket fields, references, `affected_system`, and `status`. Supplying `status` requires a staff/operator
service account and records the normal lifecycle event.

### Read Case by External Reference

`GET /api/v1/cases/external/<provider>/<external_id>/` requires `cases:read`.

Use this when a gateway/watchdog worker only has its own correlation ID and needs the current Open
Response Center lifecycle state.

### Add Case Note

`POST /api/v1/cases/<id>/notes/` requires `cases:note`.

```json
{
  "body": "Gateway watchdog is retrying the health check.",
  "is_operator_note": true
}
```

`is_operator_note` is honored only for staff/operator service accounts. Reporter-visible notes follow
the normal first-response and notification rules.

### Add Case Event

`POST /api/v1/cases/<id>/events/` requires `cases:event`.

Use events for machine-readable observations that should appear in the case timeline without pretending
to be human conversation.

```json
{
  "external_reference": {
    "provider": "openclaw-gateway-watchdog",
    "external_id": "gateway-health-152956"
  },
  "source": "openclaw-gateway-watchdog",
  "event_type": "heartbeat_failed",
  "severity": "warning",
  "summary": "Gateway heartbeat missed its deadline.",
  "metadata": {
    "missed": 2
  },
  "occurred_at": "2026-07-22T18:57:00Z"
}
```

`source` and `event_type` must be slug values. `severity` is one of `info`, `warning`, `error`, or
`critical`. `metadata` must be a JSON object.

## Compatibility

The older `/api/tickets/...` operations-agent endpoints remain supported for existing callers. New
automation should prefer `/api/v1/cases/...` because it supports external correlation IDs, structured
machine events, and the same case bundle shape the GUI-facing service layer is being moved toward.

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
  "additional_context": "Raised by an operations agent.",
  "department_intake_12": "gateway-health"
}
```

`affected_system` may be a system slug or numeric id, and is filtered through the same visibility
rules as the reporter form. Department-specific intake fields use the same `department_intake_<field id>`
keys as the reporter form when the selected system routes to a department with extra fields.

### Read Ticket

`GET /api/tickets/<id>/` requires `tickets:read`.

Returns the ticket, messages, attachment metadata, and linked operational incidents visible to the
token's user. The serialized ticket includes an `sla` object with overall state, response/resolution
state, due timestamps, completion timestamps, and the active response/resolution windows in minutes.
It also includes `intake_field_values` for any submitted department-specific intake answers and a
`workflow_checklist` object:

```json
{
  "workflow_checklist": {
    "total": 2,
    "completed": 1,
    "open_blocking": 1,
    "items": [
      {
        "id": 10,
        "title": "Classify exposure",
        "description": "Confirm exposure and access level.",
        "blocks_closure": true,
        "is_done": false,
        "sort_order": 10,
        "completed_by": null,
        "completed_at": null
      }
    ]
  }
}
```

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
