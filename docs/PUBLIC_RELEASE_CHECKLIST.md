# Public Release Checklist

This checklist uses a two-tier model.

Hard gates must pass before publishing `open-response-center`. Advisory checks may ship with a
documented exception when the public docs clearly describe the intended deployment posture.

## Hard Gates

- Confirm the public repository is a clean initial import with no raw Git history from the private
  workbench repository.
- Run `gitleaks detect --redact` against the public candidate.
- Review `git ls-files` in the public candidate for private project-management files, local data,
  secrets, generated artifacts, and private branding assets.
- Review ignored files and directories with `git status --ignored` or equivalent before export.
- Confirm `.env`, SQLite databases, uploads, caches, static build output, logs, and temporary files
  are not included.
- Confirm `LICENSE` and `SECURITY.md` are present.
- Run the project test suite.
- Run the deployed smoke check or document why it is not applicable to the public candidate.
- Confirm public docs do not include private workspace paths, chat platform channel IDs, user IDs,
  hostnames, credentials, incident data, or private agent/OpenClaw operating notes.

## Advisory Checks

- Run `python manage.py check --deploy` against a production-like environment.
- Document any deploy-hardening warnings that remain acceptable for internal/tailnet-only use.
- Confirm internet-facing deployments have separate guidance for HTTPS, HSTS, secure cookies,
  allowed hosts, CSRF trusted origins, proxy identity headers, backups, and upgrade procedures.
- Confirm the included Podman Compose path is described as internal/tailnet-first unless a hardened
  production configuration is provided.

## Release Record

Before publishing, record:

- Public repo name and commit SHA.
- Checklist date and reviewer.
- Hard-gate results.
- Any advisory exceptions and rationale.
