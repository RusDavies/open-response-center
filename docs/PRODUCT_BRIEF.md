# Product Brief

## Problem

Internal users need a friendly way to report problems with OpenClaw, related software, hardware, and operating infrastructure, then track progress without learning the internal incident-management workflow.

Open Response Center is scoped as an internal tool. A public/customer portal is not currently planned and should stay out of the active backlog unless a maintainer explicitly reopens that direction.

## Users

- Internal reporters who need to raise and follow issues.
- Operators who triage, investigate, and communicate status.
- OpenClaw agents that create, update, link, and summarize incident work.
- Administrators who manage systems, users, retention, and integrations.

## MVP Outcomes

- A reporter can submit an issue with structured reproduction details, affected system, impact, and attachments.
- A reporter can see status and participate in a thread.
- Operators can triage, classify, update status, and reply.
- Internal users can find reusable known-issue and runbook guidance.
- Operators can link repeated problems to knowledge-base articles.
- Users can control email notifications for status changes and new messages.
- Each item can link to a canonical workspace incident and optional engineering work.

## Success Criteria

- Five synthetic incidents can be raised and tracked end-to-end.
- Reporter-facing status remains understandable without internal jargon.
- Attachment evidence is private and retrievable.
- OpenClaw can create or update incident records from ticket events.
