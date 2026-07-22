# Deployment

## Podman MVP

The MVP deployment target is a single Django/Gunicorn container with SQLite, uploaded attachments,
collected static assets, and OpenClaw incident files stored on mounted volumes. This is suitable for
private internal testing, not a public internet service.

1. Create a local environment file:

   ```bash
   cp .env.example .env
   python - <<'PY'
   from secrets import token_urlsafe
   print(f"DJANGO_SECRET_KEY={token_urlsafe(48)}")
   PY
   ```

   Replace the placeholder `DJANGO_SECRET_KEY` in `.env` with the generated value.

2. Set the host bind and deployment-specific hostnames. `ORC_BIND_HOST` must be the machine's
   Tailscale IPv4 address so the service binds to the tailnet interface instead of localhost, LAN,
   or every interface. Include every hostname or IP address users will type into the browser:

   ```env
   ORC_BIND_HOST=100.x.y.z
   DJANGO_ALLOWED_HOSTS=100.x.y.z,host.tailnet-name.ts.net,open-response-center.example.invalid
   DJANGO_CSRF_TRUSTED_ORIGINS=http://100.x.y.z:8000,https://host.tailnet-name.ts.net,https://open-response-center.example.invalid
   ```

3. Build and start with Podman Compose:

   ```bash
   podman compose -f podman-compose.yml up --build
   ```

4. Seed local demo data when needed:

   ```bash
   podman compose -f podman-compose.yml exec web python manage.py seed_demo
   ```

   This creates `operator` / `operator` and `reporter` / `reporter` logins, sample systems, sample
   tickets, and reference department workflows for Security, Software, Operations, Hardware, and Admin
   queues.

5. Open `http://<tailscale-ip>:8000/` from a tailnet device.

The container runs migrations and `collectstatic` before starting Gunicorn. Static files are served by
WhiteNoise from `DJANGO_STATIC_ROOT`.
The Compose port mapping binds to `${ORC_BIND_HOST}:8000`, so Podman publishes the app only on the
configured Tailscale IPv4 interface. `DJANGO_ALLOWED_HOSTS` still controls which HTTP Host headers
Django will accept.

## Public Deployment Posture

The included Podman Compose setup is the quick internal/tailnet path. It is suitable for private
testing or trusted internal deployments, not direct exposure to the public internet.

For an internet-facing deployment, put the app behind a hardened HTTPS reverse proxy and complete the
production checklist before accepting traffic:

- Set `DJANGO_DEBUG=false`.
- Use a unique, high-entropy `DJANGO_SECRET_KEY`.
- Restrict `DJANGO_ALLOWED_HOSTS` to the real public hostnames.
- Set `DJANGO_CSRF_TRUSTED_ORIGINS` to the exact HTTPS origins served by the proxy.
- Enable HTTPS redirect at the proxy or Django boundary.
- Enable HSTS after confirming the service is correctly served over HTTPS.
- Set secure session and CSRF cookies in production settings.
- Strip client-supplied identity headers before enabling remote-user authentication.
- Terminate TLS with modern ciphers and automatic certificate renewal.
- Keep SQLite only for small/internal deployments; use a managed database or explicit backup plan for
  production use.
- Back up the database, uploaded media, and any incident/evidence storage before upgrades.
- Run `python manage.py check --deploy` against the production environment and resolve warnings or
  explicitly document accepted residual risk.

The public open-core repo should present both paths: internal/tailnet Compose for fast evaluation and
a separate internet-facing hardening checklist for production operators.

## Persistent Volumes

The default `podman-compose.yml` defines named volumes:

- `open-response-center-data` for SQLite and ticket uploads.
- `open-response-center-static` for collected static files.
- `open-response-center-openclaw` for OpenClaw workspace incident files.

Volume mounts use Podman's `:U` option so the rootless container user can write SQLite, uploads,
static files, and workspace incident data.

For a real OpenClaw deployment, replace the `open-response-center-openclaw:/workspace` named volume
with a bind mount to the workspace root that should receive `incidents/` updates, preserving the
`:U` option or otherwise ensuring UID 10001 can write there.

## Environment

- `DJANGO_SECRET_KEY`: required secret key. Do not reuse the example value.
- `DJANGO_DEBUG`: set `false` for deployment.
- `DJANGO_ALLOWED_HOSTS`: comma-separated hostnames.
- `DJANGO_CSRF_TRUSTED_ORIGINS`: comma-separated `https://...` origins when behind a proxy.
- `DJANGO_SQLITE_PATH`: SQLite database path inside the container.
- `DJANGO_MEDIA_ROOT`: upload storage path inside the container.
- `DJANGO_STATIC_ROOT`: collected static files path inside the container.
- `OPENCLAW_WORKSPACE_ROOT`: workspace root used by the incident bridge.
- `DEFAULT_FROM_EMAIL`: sender address for notification email.
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USE_TLS`, `SMTP_USER`, `SMTP_PASSWORD`: SMTP settings. If
  `SMTP_HOST` is unset, Django uses the console email backend.
- `GUNICORN_WORKERS`: Gunicorn worker count.
- `ORC_ENABLE_REMOTE_USER_AUTH`: set `true` only behind a trusted identity-aware reverse proxy.
- `ORC_REMOTE_USER_HEADER`, `ORC_REMOTE_USER_EMAIL_HEADER`, `ORC_REMOTE_USER_FIRST_NAME_HEADER`,
  `ORC_REMOTE_USER_LAST_NAME_HEADER`: WSGI header keys populated by the proxy.
- `ORC_REMOTE_USER_STAFF_HEADER`: optional staff flag header. Leave blank unless the proxy has a
  reliable internal operator/admin group signal.

When remote-user auth is enabled, the reverse proxy must strip client-supplied identity headers before
setting its own. Otherwise you have built a username vending machine. Very convenient, deeply bad.

## Smoke Checks

After startup, run the reusable deployed acceptance smoke test:

```bash
python scripts/compose_smoke_test.py --build
```

The smoke test starts the Podman Compose stack, waits for the HTTP surface, runs migrations and demo
seeding in the container, logs in as the demo reporter, confirms the published knowledge-base article,
submits a ticket with an attachment, logs in as the demo operator, moves the ticket into active triage,
promotes it to an OpenClaw workspace incident, creates a temporary operations-agent API token, exercises
the JSON ticket/message/status and incident-promotion API flow, runs incident sync, checks attachment
cleanup, and runs Django's SLA report and deployment checks.

For an already-running stack:

```bash
python scripts/compose_smoke_test.py --no-up
```

The lower-level checks are still useful when debugging a specific subsystem:

```bash
podman compose -f podman-compose.yml exec web python manage.py check --deploy
podman compose -f podman-compose.yml exec web python manage.py cleanup_attachments
podman compose -f podman-compose.yml exec web python manage.py sla_report --breached-only
```

`check --deploy` may still warn about TLS/proxy hardening until the container is placed behind the
actual internal reverse proxy.
