# Requirements

## Functional Requirements

- Authorized users can create issue/incident reports.
- Internal identity can be supplied by a trusted reverse proxy through explicitly enabled remote-user headers.
- Reports include title, affected system, impact, summary of issue, actions to repeat, expected outcome, actual outcome, optional additional context, and optional evidence attachments.
- Systems can route reports to a default department and workflow template.
- Departments can define extra intake fields for reports that need department-specific structured data.
- Department workflow templates can generate operator checklist items for each ticket.
- Operator ticket queues can be filtered by department responsibility and preserve admin-wide visibility.
- Blocking workflow checklist items must be completed before an operator can close the ticket.
- Users can view their submitted reports and current status.
- Users and operators can participate in a threaded discussion per report.
- Operators can add internal notes hidden from reporters.
- Operators can update lifecycle state.
- Operators can see response and resolution SLA state derived from ticket impact.
- Operators and automation can report breached open-ticket SLA targets.
- Internal users can search published knowledge-base articles for known issues, runbooks, and guidance.
- Operators can create draft or published knowledge-base articles and link them to tickets.
- Operators can draft an operator-only knowledge-base article from an existing ticket.
- Users can independently enable or disable email updates for lifecycle changes and new messages.
- Operators can link a report to a canonical `INC-...` incident.
- Operators can promote a report into an operational incident through an adapter-backed workflow.
- Operators can classify operational incidents before promotion.
- Operators can import linked workspace incident status updates back into reporter-facing ticket status.
- Promoted ticket attachments are copied into the operational incident evidence directory.
- Scoped operations-agent service accounts can use authenticated JSON APIs to create and read tickets,
  add ticket messages, update lifecycle fields, and promote tickets to operational incidents.
- Scoped operations-agent service accounts can upsert and query cases by external provider/correlation
  IDs so gateway/watchdog automation can hand off repeat observations idempotently.
- The system keeps structured machine-observation events separate from human ticket messages while
  exposing both in the case API timeline.
- Reporter evidence upload screens guide users to redact secrets and unrelated private data before submitting logs or screenshots.
- Operators can link a report to engineering work when needed.
- The system keeps an audit trail of status changes, comments, attachment events, and integration events.

## Non-Functional Requirements

- Private by default.
- Mobile-friendly enough for quick reporting.
- Backups must include metadata and attachment storage.
- Attachments must have size limits and safe storage paths.
- Ticket attachments should be retained for 90 days after ticket closure by default, then removed by an explicit cleanup command.
- The app must be deployable under Podman with persistent data, upload, static, and OpenClaw workspace storage.
- The implementation should be small enough for OpenClaw agents to understand and maintain.

## Open Questions

- FastAPI or Django for the first spike?
- Local filesystem attachments first, or object storage from day one?
- Which identity source should authorize internal users?
- Should chat or webhook notifications be supported in addition to email?
- Should the long-term incident backend be Open Response Center-native, the workspace `incidents/` tree, or both during a transition period?
