# Architecture Notes

## Initial Bias

Use a conventional web application:

- Django web backend for the MVP spike.
- SQLite for local MVP development and private Podman MVP deployment; Postgres remains the later durable deployment target.
- Local filesystem attachment storage behind Django `FileField`; keep upload paths ignored.
- SMTP notification adapter; console email backend in local development.
- OpenClaw workspace incident adapter for the first operational incident backend.
- Server-rendered UI unless a richer frontend proves necessary.
- Optional trusted reverse-proxy identity integration for internal deployments.

## Core Domain Objects

- User
- System
- Ticket
- Department
- WorkflowTemplate
- WorkflowChecklistItemTemplate
- TicketWorkflowChecklistItem
- TicketMessage
- Attachment
- LifecycleEvent
- IncidentLink
- EngineeringLink
- NotificationPreference
- SlaPolicy
- KnowledgeBaseArticle
- TicketKnowledgeBaseLink

Current MVP implementation folds incident and engineering links into ticket reference fields. Promote
them to richer linked models only when synchronization or history requires it.

`OperationalIncident` is the first richer incident-domain model. It keeps the current OpenClaw
workspace markdown process behind an adapter boundary so the product can later become the primary incident
system without hard-wiring ticket flows to `incidents/active/*.md`.

## Integration Boundaries

- Email is an outbound notification channel, not the source of truth.
- OpenClaw incident files remain the canonical operational incident record unless a later decision changes that.
- The OpenClaw file adapter is an integration backend, not the product-domain source of truth.
- Operations-agent APIs are authenticated with scoped bearer tokens tied to Django users. Operator-grade
  lifecycle and incident actions require both the relevant API scope and a staff/operator service account.
- Ticket attachments are copied into OpenClaw incident evidence on promotion so operational incidents retain a stable evidence snapshot.
- Linked OpenClaw incident file statuses can be imported back into Open Response Center and mapped onto reporter-facing ticket statuses.
- Engineering trackers are linked when implementation work needs them, not for every ticket.

## Attachment Retention

Ticket attachments are retained while a ticket is open and for 90 days after closure. The MVP uses
the ticket `updated_at` timestamp as the closure-age proxy: any update to a closed ticket extends the
attachment retention window. Operational incident evidence copies are not removed by ticket attachment
cleanup because they belong to the incident record.

Run `python manage.py cleanup_attachments` to see attachments eligible for removal. Add `--delete` to
remove matching attachment files and their database rows. Use `--days N` to override the default
90-day retention window.

## SLA Tracking

Tickets derive response and resolution due times from their impact. `SlaPolicy` rows can override
the built-in windows per impact; if no active row exists, the app falls back to internal defaults.

The ticket stores `first_response_at` when an operator moves the ticket out of received state or
adds a reporter-visible reply. It stores `resolved_at` when a ticket enters fixed, verified, or
closed, and clears that timestamp if the ticket is reopened. The derived SLA state is `on_track`,
`at_risk`, `breached`, or `met`.

Run `python manage.py sla_report` for the open-ticket SLA queue. Add `--breached-only` to suppress
healthy rows and `--fail-on-breach` when wiring the command into automation.

## Knowledge Base

The knowledge base is internal-only. Articles can be published for all internal users or kept
operator-only. Operators can create articles directly, link articles to tickets, or draft an
operator-only runbook from a ticket's structured intake fields.

`TicketKnowledgeBaseLink` records reusable guidance attached to a ticket without turning the ticket
thread into the article source of truth. Repeated tickets should graduate into articles when the
resolution or triage steps become reusable.

## Department Workflows

Department workflows are a routing and operator-policy layer on top of tickets. `System` records can
point to a default department and workflow template. When a ticket is created, the ticket copies those
defaults, optionally applies a workflow default impact, and generates ticket-local checklist rows from
the template.

Departments can also define extra intake fields for structured data that only matters to that queue.
Those definitions are stored separately from tickets, while submitted answers are copied onto the
ticket as JSON so later changes to department field definitions do not rewrite historical reports.

Generated checklist rows are deliberately copied onto the ticket instead of read live from the template.
That preserves the operator record even if a department later edits its workflow template. Blocking
checklist rows prevent the ticket from moving to closed until an operator marks them complete.

Operator queue views default to the departments owned by the operator's groups, departments with no
assigned operator groups, unassigned tickets, and tickets already assigned to that operator. Admin
users keep full queue visibility. Operators can narrow the board and ticket list to a specific
department without changing direct ticket visibility rules.

## Security Notes

- Never expose attachments publicly by default.
- Keep all downloads authorization-checked.
- Store only hashed operations-agent bearer tokens; the raw token is shown once at creation.
- Keep operations-agent tokens scoped to the smallest action set the agent needs.
- Record who viewed/downloaded sensitive evidence if practical.
- Avoid storing secrets in tickets; the new-ticket and evidence-upload screens give reporter-facing redaction guidance.

## Local MVP Surfaces

- Reporter: ticket list, new ticket form, detail/thread, evidence upload/download.
- Reporter/internal user: published all-internal knowledge-base articles and ticket-linked guidance.
- Reporter/operator: email preference controls for status-change and thread-message notifications.
- Operator: all-ticket view, status/lifecycle update, incident/engineering references, internal notes,
  workflow checklist management, knowledge-base authoring, and ticket article links.
- Admin: Django admin for users, systems, tickets, messages, attachments, lifecycle events, and notification preferences.

## Identity Boundary

Local development keeps Django username/password login. Internal deployment can enable
`ORC_ENABLE_REMOTE_USER_AUTH=true` to trust identity headers set by a reverse proxy. The app never
trusts those headers unless this flag is explicitly enabled, and deployments must ensure the proxy
strips any client-supplied copies before adding its own.

By default the middleware reads:

- `HTTP_X_REMOTE_USER` for username
- `HTTP_X_REMOTE_EMAIL` for email
- `HTTP_X_REMOTE_FIRST_NAME` and `HTTP_X_REMOTE_LAST_NAME` for display names

Users are auto-created with unusable passwords. Staff status remains admin-managed unless
`ORC_REMOTE_USER_STAFF_HEADER` is explicitly configured.

## Deployment Surface

- `Containerfile` builds a Django/Gunicorn image.
- `podman-compose.yml` runs the app with persistent volumes for SQLite, uploads, static files, and OpenClaw incident workspace data.
- WhiteNoise serves collected static files inside the container for the private MVP.
- `docs/DEPLOYMENT.md` records setup, environment variables, and smoke checks.
