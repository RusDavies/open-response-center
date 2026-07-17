# Open Response Center

Open Response Center is an internal-first support and incident intake app for teams that need a
clear place to receive reports, triage issues, communicate status, and preserve evidence.

It is built as an open-core product: the public repo contains the reusable ticketing and incident
intake core, while commercial or organization-specific extensions can live separately.

## What It Does

- Provides authenticated ticket intake for internal reporters.
- Captures structured reproduction details: summary, repeat actions, expected outcome, actual
  outcome, and additional context.
- Supports attachments, private message threads, operator notes, status changes, and audit history.
- Gives reporters a clear lifecycle without exposing every internal repair detail.
- Provides operator workflows for triage, classification, checklists, and follow-up.
- Includes knowledge-base support for known issues and runbooks.
- Supports email notifications for status changes and new messages.
- Offers an adapter boundary for promoting tickets into operational incident systems.

## Product Shape

Open Response Center is a support-ticket intake product, not a general project tracker.

Reporter-facing statuses are intentionally plain:

- received
- triaged
- in progress
- waiting on reporter
- waiting on vendor or external dependency
- fixed
- verified
- closed

Operator-facing work can link to incident records, engineering issues, pull requests, deployment
evidence, and other operational systems through adapters.

## Open-Core Boundary

The open-core project includes ticket intake, lifecycle management, comments, attachments, operator
workflows, public documentation, tests, development setup, the MIT license, and security guidance.

The public distribution uses neutral `Open Response Center` branding by default. RedShieldKnight may
be mentioned as the project origin or sponsor in public documentation, but private branding packages
and organization-specific extensions belong outside the open-core repo.

Optional integrations, including a sanitized OpenClaw reference adapter, must not include private
workspace paths, real incident data, credentials, chat platform IDs, hostnames, or project-management
context.

## Local Development

The current implementation uses Django with SQLite for local development.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python manage.py migrate
.venv/bin/python manage.py seed_demo
.venv/bin/python manage.py runserver 127.0.0.1:8000
```

Demo logins:

- reporter: `reporter` / `reporter`
- operator/admin: `operator` / `operator`

Local surfaces:

- ticket list: `http://127.0.0.1:8000/`
- new ticket: `http://127.0.0.1:8000/tickets/new/`
- knowledge base: `http://127.0.0.1:8000/knowledge-base/`
- admin: `http://127.0.0.1:8000/admin/`

## Podman Deployment

The project includes a `Containerfile`, `podman-compose.yml`, and deployment notes in
`docs/DEPLOYMENT.md`. The included Compose path is intended for local, internal, or tailnet
deployments. Internet-facing deployments require the hardening guidance in the deployment docs.

```bash
cp .env.example .env
podman compose -f podman-compose.yml up --build
```

Run the deployed acceptance smoke test:

```bash
python scripts/compose_smoke_test.py --no-up
```

## Documentation

- `docs/PRODUCT_BRIEF.md`: product goals and success criteria.
- `docs/ARCHITECTURE.md`: application architecture and operational model.
- `docs/API.md`: operations API notes.
- `docs/DEPLOYMENT.md`: Podman and production deployment guidance.
- `docs/PUBLIC_OPENCLAW_ADAPTER_BOUNDARY.md`: public boundary for the optional OpenClaw adapter.
- `docs/PUBLIC_RELEASE_CHECKLIST.md`: release gates and advisory checks.
- `SECURITY.md`: vulnerability reporting and supported deployment assumptions.

## License

Open Response Center is released under the MIT License. See `LICENSE`.
