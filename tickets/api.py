from __future__ import annotations

import json
from typing import Any, Callable

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.http import HttpRequest, JsonResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .forms import IncidentClassificationForm, MessageForm, OperatorUpdateForm, TicketCreateForm
from .incident_adapters import OpenClawWorkspaceIncidentAdapter
from .models import (
    Attachment,
    OperationsAgentScope,
    OperationsAgentToken,
    OperationalIncident,
    System,
    Ticket,
    TicketMessage,
)
from .notifications import notify_ticket_watchers


class ApiError(ValueError):
    def __init__(self, message: str, *, status: int = 400, errors: dict[str, Any] | None = None):
        super().__init__(message)
        self.status = status
        self.errors = errors or {}


def _json_error(message: str, *, status: int, errors: dict[str, Any] | None = None) -> JsonResponse:
    payload: dict[str, Any] = {"error": message}
    if errors:
        payload["errors"] = errors
    return JsonResponse(payload, status=status)


def _bearer_token(request: HttpRequest) -> str:
    authorization = request.headers.get("Authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return ""
    return token.strip()


def _authenticate(request: HttpRequest, scope: str) -> OperationsAgentToken | JsonResponse:
    raw_token = _bearer_token(request)
    prefix = OperationsAgentToken.prefix_from_raw_token(raw_token)
    if not prefix:
        return _json_error("Missing or invalid bearer token.", status=401)
    try:
        agent_token = OperationsAgentToken.objects.select_related("user").get(prefix=prefix, is_active=True)
    except OperationsAgentToken.DoesNotExist:
        return _json_error("Missing or invalid bearer token.", status=401)
    if not agent_token.token_matches(raw_token):
        return _json_error("Missing or invalid bearer token.", status=401)
    if not agent_token.has_scope(scope):
        return _json_error(f"Token lacks required scope: {scope}.", status=403)
    agent_token.last_used_at = timezone.now()
    agent_token.save(update_fields=["last_used_at"])
    return agent_token


def _parse_json(request: HttpRequest) -> dict[str, Any]:
    if not request.body:
        return {}
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ApiError("Request body must be valid JSON.") from exc
    if not isinstance(payload, dict):
        raise ApiError("Request body must be a JSON object.")
    return payload


def _require_staff(agent_token: OperationsAgentToken) -> JsonResponse | None:
    if not agent_token.user.is_staff:
        return _json_error("This API action requires a staff/operator service account.", status=403)
    return None


def _field_errors(form) -> dict[str, list[str]]:
    return {field: [str(error) for error in errors] for field, errors in form.errors.items()}


def _serialize_workflow_checklist(ticket: Ticket) -> dict[str, Any]:
    items = [
        {
            "id": item.pk,
            "title": item.title,
            "description": item.description,
            "blocks_closure": item.blocks_closure,
            "is_done": item.is_done,
            "sort_order": item.sort_order,
            "completed_by": item.completed_by.get_username() if item.completed_by else None,
            "completed_at": item.completed_at.isoformat() if item.completed_at else None,
        }
        for item in ticket.workflow_items.all()
    ]
    return {
        "total": len(items),
        "completed": sum(1 for item in items if item["is_done"]),
        "open_blocking": sum(1 for item in items if item["blocks_closure"] and not item["is_done"]),
        "items": items,
    }


def _serialize_ticket(ticket: Ticket) -> dict[str, Any]:
    sla = ticket.sla_summary
    return {
        "id": ticket.pk,
        "title": ticket.title,
        "status": ticket.status,
        "impact": ticket.impact,
        "affected_system": ticket.affected_system.slug if ticket.affected_system else None,
        "department": ticket.department.slug if ticket.department else None,
        "workflow_template": ticket.workflow_template.name if ticket.workflow_template else None,
        "reporter": ticket.reporter.get_username(),
        "operator": ticket.operator.get_username() if ticket.operator else None,
        "incident_reference": ticket.incident_reference or None,
        "engineering_reference": ticket.engineering_reference or None,
        "issue_summary": ticket.issue_summary,
        "reproduction_steps": ticket.reproduction_steps,
        "expected_outcome": ticket.expected_outcome,
        "actual_outcome": ticket.actual_outcome,
        "additional_context": ticket.additional_context,
        "intake_field_values": ticket.intake_field_values,
        "workflow_checklist": _serialize_workflow_checklist(ticket),
        "sla": {
            "state": sla["state"],
            "response_state": sla["response_state"],
            "resolution_state": sla["resolution_state"],
            "state_label": sla["state_label"],
            "response_state_label": sla["response_state_label"],
            "resolution_state_label": sla["resolution_state_label"],
            "response_due_at": sla["response_due_at"].isoformat(),
            "resolution_due_at": sla["resolution_due_at"].isoformat(),
            "first_response_at": sla["first_response_at"].isoformat() if sla["first_response_at"] else None,
            "resolved_at": sla["resolved_at"].isoformat() if sla["resolved_at"] else None,
            "response_minutes": sla["response_minutes"],
            "resolution_minutes": sla["resolution_minutes"],
        },
        "created_at": ticket.created_at.isoformat(),
        "updated_at": ticket.updated_at.isoformat(),
    }


def _serialize_message(message: TicketMessage) -> dict[str, Any]:
    return {
        "id": message.pk,
        "ticket": message.ticket_id,
        "author": message.author.get_username(),
        "body": message.body,
        "is_operator_note": message.is_operator_note,
        "created_at": message.created_at.isoformat(),
    }


def _serialize_incident(incident: OperationalIncident) -> dict[str, Any]:
    return {
        "id": incident.pk,
        "ticket": incident.ticket_id,
        "backend": incident.backend,
        "reference": incident.reference,
        "title": incident.title,
        "status": incident.status,
        "scope": incident.scope,
        "actionability": incident.actionability,
        "access_level": incident.access_level,
        "exposure": incident.exposure,
        "risk": incident.risk,
        "p_level": incident.p_level,
        "human_input_required": incident.human_input_required,
        "path": incident.path,
        "evidence_path": incident.evidence_path,
        "created_by": incident.created_by.get_username(),
        "created_at": incident.created_at.isoformat(),
        "updated_at": incident.updated_at.isoformat(),
    }


def _get_api_ticket(agent_token: OperationsAgentToken, pk: int) -> Ticket:
    ticket = get_object_or_404(
        Ticket.objects.select_related(
            "affected_system",
            "department",
            "workflow_template",
            "reporter",
            "operator",
        ).prefetch_related("operational_incidents", "workflow_items__completed_by"),
        pk=pk,
    )
    if not ticket.can_be_viewed_by(agent_token.user):
        raise ApiError("Ticket not found.", status=404)
    return ticket


def _api_view(scope: str):
    def decorator(handler: Callable[[HttpRequest, OperationsAgentToken], JsonResponse]):
        def wrapped(request: HttpRequest, *args, **kwargs) -> JsonResponse:
            agent_token = _authenticate(request, scope)
            if isinstance(agent_token, JsonResponse):
                return agent_token
            try:
                return handler(request, agent_token, *args, **kwargs)
            except ApiError as exc:
                return _json_error(str(exc), status=exc.status, errors=exc.errors)

        return csrf_exempt(wrapped)

    return decorator


def _ticket_create_data(payload: dict[str, Any]) -> dict[str, Any]:
    data = dict(payload)
    affected_system = data.get("affected_system")
    if affected_system and not str(affected_system).isdigit():
        try:
            data["affected_system"] = System.objects.get(slug=affected_system).pk
        except System.DoesNotExist as exc:
            raise ApiError("Unknown affected_system slug.", errors={"affected_system": ["Unknown system."]}) from exc
    return data


def _operator_update_data(payload: dict[str, Any], ticket: Ticket) -> dict[str, Any]:
    user_model = get_user_model()
    data = {
        "status": payload.get("status", ticket.status),
        "operator": payload.get("operator", ticket.operator_id or ""),
        "incident_reference": payload.get("incident_reference", ticket.incident_reference),
        "engineering_reference": payload.get("engineering_reference", ticket.engineering_reference),
        "note": payload.get("note", ""),
    }
    operator = data["operator"]
    if operator and not str(operator).isdigit():
        try:
            data["operator"] = user_model.objects.get(username=operator).pk
        except user_model.DoesNotExist as exc:
            raise ApiError("Unknown operator username.", errors={"operator": ["Unknown user."]}) from exc
    return data


@require_http_methods(["POST"])
@_api_view(OperationsAgentScope.TICKETS_CREATE)
def api_ticket_create(request: HttpRequest, agent_token: OperationsAgentToken) -> JsonResponse:
    payload = _parse_json(request)
    form = TicketCreateForm(_ticket_create_data(payload), user=agent_token.user)
    if not form.is_valid():
        raise ApiError("Ticket payload is invalid.", errors=_field_errors(form))
    ticket = form.save(commit=False)
    ticket.reporter = agent_token.user
    ticket.save()
    ticket.generate_workflow_checklist()
    TicketMessage.objects.create(ticket=ticket, author=agent_token.user, body=ticket.description)
    return JsonResponse({"ticket": _serialize_ticket(ticket)}, status=201)


@require_http_methods(["GET"])
@_api_view(OperationsAgentScope.TICKETS_READ)
def api_ticket_detail(request: HttpRequest, agent_token: OperationsAgentToken, pk: int) -> JsonResponse:
    ticket = _get_api_ticket(agent_token, pk)
    return JsonResponse(
        {
            "ticket": _serialize_ticket(ticket),
            "messages": [_serialize_message(message) for message in ticket.messages.select_related("author")],
            "attachments": [
                {
                    "id": attachment.pk,
                    "original_name": attachment.original_name,
                    "size_bytes": attachment.size_bytes,
                    "created_at": attachment.created_at.isoformat(),
                }
                for attachment in Attachment.objects.filter(ticket=ticket)
            ],
            "operational_incidents": [
                _serialize_incident(incident) for incident in ticket.operational_incidents.select_related("created_by")
            ],
        }
    )


@require_http_methods(["POST"])
@_api_view(OperationsAgentScope.TICKETS_MESSAGE)
def api_ticket_message(request: HttpRequest, agent_token: OperationsAgentToken, pk: int) -> JsonResponse:
    ticket = _get_api_ticket(agent_token, pk)
    payload = _parse_json(request)
    form = MessageForm(payload)
    if not form.is_valid():
        raise ApiError("Message payload is invalid.", errors=_field_errors(form))
    message = form.save(commit=False)
    message.ticket = ticket
    message.author = agent_token.user
    message.is_operator_note = bool(agent_token.user.is_staff and payload.get("is_operator_note"))
    message.save()
    if agent_token.user.is_staff and not message.is_operator_note:
        ticket.record_first_response()
    if not message.is_operator_note:
        notify_ticket_watchers(
            ticket,
            f"New message on Open Response Center ticket #{ticket.pk}",
            f"{agent_token.user} wrote via operations-agent API:\n\n{message.body}",
            event="thread",
            exclude_user_id=agent_token.user.id,
        )
    return JsonResponse({"message": _serialize_message(message)}, status=201)


@require_http_methods(["POST"])
@_api_view(OperationsAgentScope.TICKETS_UPDATE)
def api_ticket_update(request: HttpRequest, agent_token: OperationsAgentToken, pk: int) -> JsonResponse:
    staff_error = _require_staff(agent_token)
    if staff_error:
        return staff_error
    ticket = _get_api_ticket(agent_token, pk)
    old_status = ticket.status
    payload = _parse_json(request)
    form = OperatorUpdateForm(_operator_update_data(payload, ticket), instance=ticket)
    if not form.is_valid():
        raise ApiError("Ticket update payload is invalid.", errors=_field_errors(form))
    updated_ticket = form.save(commit=False)
    new_status = form.cleaned_data["status"]
    note = form.cleaned_data.get("note", "")
    updated_ticket.status = old_status
    updated_ticket.save()
    if old_status != new_status:
        updated_ticket.transition_to(status=new_status, actor=agent_token.user, note=note)
        notify_ticket_watchers(
            updated_ticket,
            f"Open Response Center ticket #{updated_ticket.pk} moved to {updated_ticket.get_status_display()}",
            note or f"Status changed from {old_status} to {new_status}.",
            event="status",
            exclude_user_id=agent_token.user.id,
        )
    return JsonResponse({"ticket": _serialize_ticket(updated_ticket)})


@require_http_methods(["POST"])
@_api_view(OperationsAgentScope.INCIDENTS_PROMOTE)
def api_ticket_promote_incident(request: HttpRequest, agent_token: OperationsAgentToken, pk: int) -> JsonResponse:
    staff_error = _require_staff(agent_token)
    if staff_error:
        return staff_error
    ticket = _get_api_ticket(agent_token, pk)
    payload = _parse_json(request)
    form = IncidentClassificationForm(payload)
    if not form.is_valid():
        raise ApiError("Incident classification payload is invalid.", errors=_field_errors(form))
    try:
        result = OpenClawWorkspaceIncidentAdapter().create_from_ticket(
            ticket=ticket,
            actor=agent_token.user,
            classification=form.cleaned_data,
        )
    except ValidationError as exc:
        raise ApiError(str(exc)) from exc
    return JsonResponse(
        {
            "created": result.created,
            "incident": _serialize_incident(result.incident),
            "ticket": _serialize_ticket(result.incident.ticket),
        },
        status=201 if result.created else 200,
    )
