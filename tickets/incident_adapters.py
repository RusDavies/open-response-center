from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from django.conf import settings
from django.db import transaction
from django.template.defaultfilters import slugify
from django.utils.text import get_valid_filename
from django.utils import timezone

from .models import (
    IncidentAccessLevel,
    IncidentActionability,
    IncidentBackend,
    IncidentExposure,
    IncidentPLevel,
    IncidentRisk,
    IncidentScope,
    LifecycleEvent,
    OperationalIncident,
    HumanInputRequired,
    Ticket,
    TicketStatus,
)


@dataclass(frozen=True)
class IncidentCreationResult:
    incident: OperationalIncident
    created: bool


@dataclass(frozen=True)
class IncidentSyncResult:
    incident: OperationalIncident
    previous_incident_status: str
    workspace_status: str
    previous_ticket_status: str
    new_ticket_status: str
    changed: bool
    ticket_changed: bool
    note: str


class OpenClawWorkspaceIncidentAdapter:
    backend = IncidentBackend.OPENCLAW_WORKSPACE

    def __init__(self, workspace_root: Path | None = None):
        self.workspace_root = Path(workspace_root or settings.OPENCLAW_WORKSPACE_ROOT)
        self.incidents_root = self.workspace_root / "incidents"
        self.active_root = self.incidents_root / "active"
        self.evidence_root = self.incidents_root / "evidence"
        self.index_path = self.incidents_root / "INDEX.md"

    @transaction.atomic
    def create_from_ticket(self, *, ticket: Ticket, actor, classification: dict | None = None) -> IncidentCreationResult:
        existing = ticket.operational_incidents.filter(backend=self.backend).first()
        if existing:
            if not ticket.incident_reference:
                ticket.incident_reference = existing.reference
                ticket.save(update_fields=["incident_reference", "updated_at"])
            return IncidentCreationResult(existing, created=False)

        self.active_root.mkdir(parents=True, exist_ok=True)
        self.evidence_root.mkdir(parents=True, exist_ok=True)
        self.incidents_root.mkdir(parents=True, exist_ok=True)

        classification = self._classification_defaults() | (classification or {})
        reference, slug = self._next_reference(ticket)
        incident_path = self.active_root / f"{reference}-{slug}.md"
        evidence_path = self.evidence_root / f"{reference}-{slug}"
        evidence_path.mkdir(parents=True, exist_ok=True)
        copied_attachments = self._copy_attachments(ticket=ticket, evidence_path=evidence_path)

        content = self._render_incident(
            ticket=ticket,
            reference=reference,
            evidence_path=evidence_path,
            classification=classification,
            copied_attachments=copied_attachments,
        )
        incident_path.write_text(content, encoding="utf-8")
        self._update_index(reference=reference, ticket=ticket, classification=classification)

        incident = OperationalIncident.objects.create(
            ticket=ticket,
            backend=self.backend,
            reference=reference,
            title=ticket.title,
            status="intake",
            scope=classification["scope"],
            actionability=classification["actionability"],
            access_level=classification["access_level"],
            exposure=classification["exposure"],
            risk=classification["risk"],
            p_level=classification["p_level"],
            human_input_required=classification["human_input_required"],
            classification_note=classification.get("classification_note", ""),
            path=str(incident_path.relative_to(self.workspace_root)),
            evidence_path=str(evidence_path.relative_to(self.workspace_root)),
            created_by=actor,
            metadata={
                "adapter": "OpenClawWorkspaceIncidentAdapter",
                "source_ticket_id": ticket.pk,
                "classification": classification,
                "copied_attachments": copied_attachments,
            },
        )
        previous_reference = ticket.incident_reference
        ticket.incident_reference = reference
        ticket.save(update_fields=["incident_reference", "updated_at"])
        LifecycleEvent.objects.create(
            ticket=ticket,
            actor=actor,
            previous_status=ticket.status,
            new_status=ticket.status,
            note=(
                f"Linked OpenClaw workspace incident {reference} ({classification['p_level']}/{classification['risk']})."
                if not previous_reference
                else f"Changed OpenClaw workspace incident link from {previous_reference} to {reference}."
            ),
        )
        return IncidentCreationResult(incident, created=True)

    def sync_linked_incidents(self, *, actor=None, dry_run: bool = False) -> list[IncidentSyncResult]:
        results = []
        incidents = OperationalIncident.objects.filter(backend=self.backend).select_related("ticket", "created_by")
        for incident in incidents:
            workspace_status = self._read_workspace_status(incident)
            if not workspace_status:
                continue
            result = self._sync_incident_status(
                incident=incident,
                workspace_status=workspace_status,
                actor=actor or incident.created_by,
                dry_run=dry_run,
            )
            results.append(result)
        return results

    def _read_workspace_status(self, incident: OperationalIncident) -> str:
        if not incident.path:
            return ""
        incident_path = self.workspace_root / incident.path
        if not incident_path.exists():
            return ""
        for line in incident_path.read_text(encoding="utf-8").splitlines():
            match = re.match(r"^Status:\s*(?P<status>.+?)\s*$", line)
            if match:
                return self._normalize_workspace_status(match.group("status"))
        return ""

    def _sync_incident_status(
        self,
        *,
        incident: OperationalIncident,
        workspace_status: str,
        actor,
        dry_run: bool,
    ) -> IncidentSyncResult:
        previous_incident_status = incident.status
        previous_ticket_status = incident.ticket.status
        target_ticket_status = self._ticket_status_for_workspace_status(workspace_status) or previous_ticket_status
        changed = previous_incident_status != workspace_status
        ticket_changed = target_ticket_status != previous_ticket_status
        note = self._sync_note(
            incident=incident,
            workspace_status=workspace_status,
            target_ticket_status=target_ticket_status,
            ticket_changed=ticket_changed,
        )

        if not dry_run and changed:
            metadata = incident.metadata | {
                "last_workspace_status": workspace_status,
                "last_workspace_sync_at": timezone.now().isoformat(timespec="seconds"),
            }
            incident.status = workspace_status
            incident.metadata = metadata
            incident.save(update_fields=["status", "metadata", "updated_at"])
            if ticket_changed:
                incident.ticket.transition_to(status=target_ticket_status, actor=actor, note=note)
            else:
                LifecycleEvent.objects.create(
                    ticket=incident.ticket,
                    actor=actor,
                    previous_status=previous_ticket_status,
                    new_status=previous_ticket_status,
                    note=note,
                )

        return IncidentSyncResult(
            incident=incident,
            previous_incident_status=previous_incident_status,
            workspace_status=workspace_status,
            previous_ticket_status=previous_ticket_status,
            new_ticket_status=target_ticket_status,
            changed=changed,
            ticket_changed=ticket_changed,
            note=note,
        )

    def _normalize_workspace_status(self, status: str) -> str:
        normalized = status.strip().lower()
        normalized = re.sub(r"[^a-z0-9]+", "_", normalized)
        return normalized.strip("_")

    def _ticket_status_for_workspace_status(self, status: str) -> str:
        status_map = {
            "triaged": TicketStatus.TRIAGED,
            "in_progress": TicketStatus.IN_PROGRESS,
            "investigating": TicketStatus.IN_PROGRESS,
            "investigation": TicketStatus.IN_PROGRESS,
            "remediating": TicketStatus.IN_PROGRESS,
            "mitigating": TicketStatus.IN_PROGRESS,
            "waiting_on_reporter": TicketStatus.WAITING_ON_REPORTER,
            "needs_reporter": TicketStatus.WAITING_ON_REPORTER,
            "waiting_on_vendor": TicketStatus.WAITING_ON_VENDOR,
            "pending_external": TicketStatus.WAITING_ON_VENDOR,
            "blocked_external": TicketStatus.WAITING_ON_VENDOR,
            "fixed": TicketStatus.FIXED,
            "resolved": TicketStatus.FIXED,
            "mitigated": TicketStatus.FIXED,
            "contained": TicketStatus.FIXED,
            "verified": TicketStatus.VERIFIED,
            "validated": TicketStatus.VERIFIED,
            "closed": TicketStatus.CLOSED,
            "done": TicketStatus.CLOSED,
            "complete": TicketStatus.CLOSED,
            "completed": TicketStatus.CLOSED,
        }
        return status_map.get(status, "")

    def _sync_note(
        self,
        *,
        incident: OperationalIncident,
        workspace_status: str,
        target_ticket_status: str,
        ticket_changed: bool,
    ) -> str:
        if ticket_changed:
            return (
                f"Synced OpenClaw workspace incident {incident.reference} status '{workspace_status}' "
                f"to reporter-facing ticket status '{target_ticket_status}'."
            )
        return (
            f"Synced OpenClaw workspace incident {incident.reference} status '{workspace_status}' "
            "with no reporter-facing status change."
        )

    def _classification_defaults(self) -> dict:
        return {
            "scope": IncidentScope.OWNED_SOFTWARE,
            "actionability": IncidentActionability.AUTO_FIX,
            "access_level": IncidentAccessLevel.LOCAL_SHELL,
            "exposure": IncidentExposure.PRIVATE_CHANNEL,
            "risk": IncidentRisk.MEDIUM,
            "p_level": IncidentPLevel.P3,
            "human_input_required": HumanInputRequired.NO,
            "classification_note": "",
        }

    def _next_reference(self, ticket: Ticket) -> tuple[str, str]:
        today = timezone.localdate().isoformat()
        pattern = re.compile(rf"INC-{re.escape(today)}-(\d{{3}})")
        highest = 0
        for path in self.incidents_root.rglob(f"INC-{today}-*.md"):
            match = pattern.search(path.name)
            if match:
                highest = max(highest, int(match.group(1)))
        slug = slugify(ticket.title)[:72] or f"ticket-{ticket.pk}"
        for offset in range(1, 1000):
            reference = f"INC-{today}-{highest + offset:03d}"
            if not (self.active_root / f"{reference}-{slug}.md").exists():
                return reference, slug
        raise RuntimeError("Could not allocate an incident reference.")

    def _copy_attachments(self, *, ticket: Ticket, evidence_path: Path) -> list[dict]:
        copied_attachments = []
        for attachment in ticket.attachments.all():
            destination_name = self._evidence_filename(attachment)
            destination = evidence_path / destination_name
            with attachment.file.open("rb") as source, destination.open("wb") as target:
                for chunk in source.chunks():
                    target.write(chunk)
            copied_attachments.append(
                {
                    "original_name": attachment.original_name,
                    "source": attachment.file.name,
                    "evidence_path": str(destination.relative_to(self.workspace_root)),
                    "size_bytes": attachment.size_bytes,
                    "content_type": attachment.content_type,
                }
            )
        return copied_attachments

    def _evidence_filename(self, attachment) -> str:
        original_name = Path(attachment.original_name or attachment.file.name).name
        safe_name = get_valid_filename(original_name) or "attachment"
        return f"ticket-attachment-{attachment.pk}-{safe_name}"

    def _render_incident(
        self,
        *,
        ticket: Ticket,
        reference: str,
        evidence_path: Path,
        classification: dict,
        copied_attachments: list[dict],
    ) -> str:
        now = timezone.now().isoformat(timespec="seconds")
        reporter = ticket.reporter.get_username()
        affected_system = ticket.affected_system.name if ticket.affected_system else "unspecified"
        impact = ticket.get_impact_display()
        evidence_rel = evidence_path.relative_to(self.workspace_root)
        attachment_lines = [
            f"- `{attachment['original_name']}` ({attachment['size_bytes']} bytes) copied to "
            f"`{attachment['evidence_path']}` from ticket attachment `{attachment['source']}`"
            for attachment in copied_attachments
        ]
        if not attachment_lines:
            attachment_lines = ["- No ticket attachments were present when the incident was created."]

        return f"""# {reference} {ticket.title}

Status: intake
Owner: unassigned
Reporter: {reporter}
Opened: {now}
Updated: {now}
Source: Open Response Center ticket #{ticket.pk}
Affected system: {affected_system}
Affected area: {affected_system}
Scope: {classification["scope"]}
Actionability: {classification["actionability"]}
Access level: {classification["access_level"]}
Exposure: {classification["exposure"]}
Risk: {classification["risk"]}
P-Level: {classification["p_level"]}
Human input required: {classification["human_input_required"]}

## Summary

{ticket.issue_summary or ticket.description or "No summary supplied."}

## Intake notes

Ticket: #{ticket.pk}
Impact: {impact}
Reporter-facing status: {ticket.get_status_display()}

### Steps to reproduce

{ticket.reproduction_steps or "Not supplied."}

### Expected outcome

{ticket.expected_outcome or "Not supplied."}

### Actual outcome

{ticket.actual_outcome or "Not supplied."}

### Additional context

{ticket.additional_context or "Not supplied."}

## Classification rationale

Created from a support ticket by the Open Response Center OpenClaw workspace adapter.

{classification.get("classification_note") or "No classification note supplied."}

## Impact

{impact}

## Timeline

- `{now}` — Incident opened from Open Response Center ticket #{ticket.pk}.

## Evidence

Evidence directory: `{evidence_rel}`

{chr(10).join(attachment_lines)}

## Investigation

Pending operator investigation.

## Containment / fix plan

Pending operator triage.

## Actions taken

No remediation actions have been recorded yet.

## Verification

Pending.

## Verification work queue

- [ ] Triage the promoted ticket and confirm severity. — Status: pending — Next action: review ticket #{ticket.pk}.

Next update due: after operator triage.

## Resolution

Unresolved.

## Residual risk

Unknown until investigation completes.

## Follow-up TODOs

- Keep the Open Response Center ticket and workspace incident reference linked during triage.

## Acceptance

Pending.
"""

    def _update_index(self, *, reference: str, ticket: Ticket, classification: dict) -> None:
        line = (
            f"- `{reference}` — {classification['p_level']}/{classification['risk']}/{classification['exposure']} "
            "— Status: intake — Owner: unassigned — "
            f"Created from Open Response Center ticket #{ticket.pk}: {ticket.title}"
        )
        if self.index_path.exists():
            content = self.index_path.read_text(encoding="utf-8")
        else:
            content = "# Incident Index\n\n## Active\n\n## Recently Resolved\n"
        if reference in content:
            return
        marker = "## Active\n"
        if marker in content:
            content = content.replace(marker, f"{marker}\n{line}\n", 1)
        else:
            content = f"{content.rstrip()}\n\n## Active\n\n{line}\n"
        self.index_path.write_text(content, encoding="utf-8")
