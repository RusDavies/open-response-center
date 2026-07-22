from __future__ import annotations

from dataclasses import dataclass

from django.core.exceptions import ValidationError
from django.db.models import QuerySet

from .incident_adapters import OpenClawWorkspaceIncidentAdapter, IncidentCreationResult
from .models import (
    CaseEvent,
    CaseEventSeverity,
    ExternalReference,
    Ticket,
    TicketMessage,
    TicketStatus,
    TicketWorkflowChecklistItem,
)
from .notifications import notify_ticket_watchers


class TicketOperationError(ValueError):
    pass


@dataclass(frozen=True)
class OperatorUpdateResult:
    ticket: Ticket
    checklist_items_created: int = 0
    status_changed: bool = False


def create_ticket_from_form(form, *, reporter) -> Ticket:
    ticket = form.save(commit=False)
    ticket.reporter = reporter
    ticket.save()
    ticket.generate_workflow_checklist()
    TicketMessage.objects.create(ticket=ticket, author=reporter, body=ticket.description)
    return ticket


def add_ticket_message(
    ticket: Ticket,
    *,
    author,
    body: str,
    is_operator_note: bool = False,
    notification_body: str = "",
) -> TicketMessage:
    message = TicketMessage.objects.create(
        ticket=ticket,
        author=author,
        body=body,
        is_operator_note=is_operator_note,
    )
    if author.is_staff and not is_operator_note:
        ticket.record_first_response()
    if not is_operator_note:
        notify_ticket_watchers(
            ticket,
            f"New message on Open Response Center ticket #{ticket.pk}",
            notification_body or f"{author} wrote:\n\n{message.body}",
            event="thread",
            exclude_user_id=author.id,
        )
    return message


def transition_ticket_status(ticket: Ticket, *, status: str, actor, note: str = "") -> bool:
    valid_statuses = {choice[0] for choice in TicketStatus.choices}
    if status not in valid_statuses:
        raise TicketOperationError("Unsupported lifecycle status.")
    if status == ticket.status:
        return False
    if status == TicketStatus.CLOSED and ticket.has_blocking_workflow_items():
        raise TicketOperationError("Complete blocking workflow checklist items before closing this ticket.")
    old_status = ticket.status
    ticket.transition_to(status=status, actor=actor, note=note)
    notify_ticket_watchers(
        ticket,
        f"Open Response Center ticket #{ticket.pk} moved to {ticket.get_status_display()}",
        note or f"Status changed from {old_status} to {status}.",
        event="status",
        exclude_user_id=actor.id,
    )
    return True


def update_operator_fields_from_form(ticket: Ticket, *, form, actor) -> OperatorUpdateResult:
    persisted_ticket = Ticket.objects.only("status", "workflow_template").get(pk=ticket.pk)
    old_status = persisted_ticket.status
    old_workflow_template_id = persisted_ticket.workflow_template_id
    updated_ticket = form.save(commit=False)
    new_status = form.cleaned_data["status"]
    note = form.cleaned_data.get("note", "")
    updated_ticket.status = old_status
    updated_ticket.save()

    created_count = 0
    if updated_ticket.workflow_template_id != old_workflow_template_id:
        created_count = updated_ticket.generate_workflow_checklist()

    status_changed = transition_ticket_status(updated_ticket, status=new_status, actor=actor, note=note)
    return OperatorUpdateResult(
        ticket=updated_ticket,
        checklist_items_created=created_count,
        status_changed=status_changed,
    )


def update_workflow_checklist(ticket: Ticket, *, done_ids: set[int], actor) -> None:
    for item in TicketWorkflowChecklistItem.objects.filter(ticket=ticket):
        item.set_done(is_done=item.pk in done_ids, actor=actor)


def reorder_ticket_board(
    *,
    actor,
    target_status: str,
    ticket_ids: list[int],
    moved_ticket_id: int,
    visible_tickets: QuerySet,
) -> list[int]:
    valid_statuses = {choice[0] for choice in TicketStatus.choices}
    if target_status not in valid_statuses:
        raise TicketOperationError("Unsupported lifecycle status.")
    if moved_ticket_id not in ticket_ids:
        raise TicketOperationError("Moved ticket is required.")

    visible_ticket_ids = set(visible_tickets.filter(pk__in=ticket_ids).values_list("pk", flat=True))
    if set(ticket_ids) != visible_ticket_ids:
        raise PermissionError("Board order includes tickets outside your operator queue.")

    tickets_by_id = Ticket.objects.in_bulk(ticket_ids)
    changed_statuses = []
    for index, ticket_id in enumerate(ticket_ids, start=1):
        ticket = tickets_by_id[ticket_id]
        next_position = index * 10
        position_changed = ticket.board_position != next_position
        if position_changed:
            ticket.board_position = next_position
        if ticket.status != target_status:
            transition_ticket_status(ticket, status=target_status, actor=actor, note="Moved on operator board.")
            if position_changed:
                ticket.save(update_fields=["board_position", "updated_at"])
            changed_statuses.append(ticket.pk)
        elif position_changed:
            ticket.save(update_fields=["board_position", "updated_at"])
    return changed_statuses


def create_operational_incident_from_ticket(*, ticket: Ticket, actor, classification: dict) -> IncidentCreationResult:
    try:
        return OpenClawWorkspaceIncidentAdapter().create_from_ticket(
            ticket=ticket,
            actor=actor,
            classification=classification,
        )
    except ValidationError as exc:
        raise TicketOperationError(str(exc)) from exc


def record_case_event(
    *,
    ticket: Ticket,
    event_type: str,
    summary: str,
    source: str = "open-response-center",
    severity: str = CaseEventSeverity.INFO,
    metadata: dict | None = None,
    actor=None,
    external_reference: ExternalReference | None = None,
    occurred_at=None,
) -> CaseEvent:
    return CaseEvent.objects.create(
        ticket=ticket,
        external_reference=external_reference,
        actor=actor if getattr(actor, "is_authenticated", False) else None,
        source=source,
        event_type=event_type,
        severity=severity,
        summary=summary,
        metadata=metadata or {},
        occurred_at=occurred_at,
    )
