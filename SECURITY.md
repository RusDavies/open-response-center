# Security Policy

## Reporting A Vulnerability

Please do not report security vulnerabilities in public issues.

Use GitHub private vulnerability reporting or a private GitHub security advisory for this repository
when available. Include:

- A clear description of the issue.
- Steps to reproduce, proof-of-concept details, or affected code paths.
- The likely impact.
- Any suggested fix or mitigation.

Please allow time for coordinated review and remediation before public disclosure.

## Supported Deployments

The open-core project supports two deployment postures:

- Internal or tailnet deployments using the included Podman Compose setup.
- Internet-facing deployments only after completing the production hardening guidance in
  `docs/DEPLOYMENT.md`.

The default Compose setup is not, by itself, a complete public internet production deployment.

## Sensitive Data

Reports should avoid including secrets, live credentials, private incident data, uploaded evidence,
or private workspace paths unless they are essential to the vulnerability report. If sensitive
details are required, share them only through the private reporting channel.
