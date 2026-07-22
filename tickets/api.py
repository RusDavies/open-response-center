from __future__ import annotations

import json
from typing import Any, Callable

from django.contrib.auth import get_user_model
from django.http import HttpRequest, JsonResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.text import slugify
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .forms import IncidentClassificationForm, MessageForm, OperatorUpdateForm, TicketCreateForm
from .models import (
    Attachment,
    CaseEvent,
    CaseEventSeverity,
    ExternalReference,
    OperationsAgentScope,
    OperationsAgentToken,
    OperationalIncident,
    System,
    Ticket,
    TicketMessage,
    TicketStatus,
)
from .services import (
    TicketOperationError,
    add_ticket_message,
    create_operational_incident_from_ticket,
    create_ticket_from_form,
    record_case_event,
    transition_ticket_status,
    update_operator_fields_from_form,
)


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


def _serialize_external_reference(reference: ExternalReference) -> dict[str, Any]:
    return {
        "id": reference.pk,
        "provider": reference.provider,
        "external_id": reference.external_id,
        "ticket": reference.ticket_id,
        "operational_incident": reference.operational_incident_id,
        "metadata": reference.metadata,
        "created_at": reference.created_at.isoformat(),
        "updated_at": reference.updated_at.isoformat(),
    }


def _serialize_case_event(event: CaseEvent) -> dict[str, Any]:
    return {
        "id": event.pk,
        "ticket": event.ticket_id,
        "external_reference": event.external_reference_id,
        "actor": event.actor.get_username() if event.actor else None,
        "source": event.source,
        "event_type": event.event_type,
        "severity": event.severity,
        "summary": event.summary,
        "metadata": event.metadata,
        "occurred_at": event.occurred_at.isoformat() if event.occurred_at else None,
        "created_at": event.created_at.isoformat(),
    }


def _serialize_attachments(ticket: Ticket) -> list[dict[str, Any]]:
    return [
        {
            "id": attachment.pk,
            "original_name": attachment.original_name,
            "size_bytes": attachment.size_bytes,
            "created_at": attachment.created_at.isoformat(),
        }
        for attachment in Attachment.objects.filter(ticket=ticket)
    ]


def _serialize_case(ticket: Ticket) -> dict[str, Any]:
    return {
        "ticket": _serialize_ticket(ticket),
        "messages": [_serialize_message(message) for message in ticket.messages.select_related("author")],
        "attachments": _serialize_attachments(ticket),
        "operational_incidents": [
            _serialize_incident(incident) for incident in ticket.operational_incidents.select_related("created_by")
        ],
        "external_references": [
            _serialize_external_reference(reference) for reference in ticket.external_references.all()
        ],
        "case_events": [
            _serialize_case_event(event)
            for event in ticket.case_events.select_related("actor", "external_reference").all()
        ],
    }


def _get_api_ticket(agent_token: OperationsAgentToken, pk: int) -> Ticket:
    ticket = get_object_or_404(
        Ticket.objects.select_related(
            "affected_system",
            "department",
            "workflow_template",
            "reporter",
            "operator",
        ).prefetch_related(
            "external_references",
            "operational_incidents",
            "workflow_items__completed_by",
            "case_events__actor",
            "case_events__external_reference",
        ),
        pk=pk,
    )
    if not ticket.can_be_viewed_by(agent_token.user):
        raise ApiError("Ticket not found.", status=404)
    return ticket


def _get_api_case(agent_token: OperationsAgentToken, pk: int) -> Ticket:
    return _get_api_ticket(agent_token, pk)


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


def _external_reference_data(payload: dict[str, Any]) -> dict[str, Any]:
    reference = payload.get("external_reference")
    if not isinstance(reference, dict):
        raise ApiError("external_reference is required.", errors={"external_reference": ["This field is required."]})
    provider = str(reference.get("provider", "")).strip()
    external_id = str(reference.get("external_id", "")).strip()
    metadata = reference.get("metadata", {})
    if not provider:
        raise ApiError("external_reference.provider is required.", errors={"external_reference.provider": ["Required."]})
    if slugify(provider) != provider:
        raise ApiError(
            "external_reference.provider must be a slug.",
            errors={"external_reference.provider": ["Use lowercase letters, numbers, underscores, or hyphens."]},
        )
    if not external_id:
        raise ApiError(
            "external_reference.external_id is required.",
            errors={"external_reference.external_id": ["Required."]},
        )
    if not isinstance(metadata, dict):
        raise ApiError(
            "external_reference.metadata must be an object.",
            errors={"external_reference.metadata": ["Must be an object."]},
        )
    return {"provider": provider, "external_id": external_id, "metadata": metadata}


def _update_ticket_from_case_payload(ticket: Ticket, payload: dict[str, Any]) -> list[str]:
    mutable_fields = [
        "title",
        "impact",
        "issue_summary",
        "reproduction_steps",
        "expected_outcome",
        "actual_outcome",
        "additional_context",
        "incident_reference",
        "engineering_reference",
    ]
    update_fields = []
    for field in mutable_fields:
        if field in payload and getattr(ticket, field) != payload[field]:
            setattr(ticket, field, payload[field])
            update_fields.append(field)
    if "affected_system" in payload:
        affected_system = payload["affected_system"]
        if affected_system == "" or affected_system is None:
            system = None
        elif str(affected_system).isdigit():
            system = System.visible_to(ticket.reporter).filter(pk=int(affected_system)).first()
        else:
            system = System.visible_to(ticket.reporter).filter(slug=str(affected_system)).first()
        if affected_system != "" and affected_system is not None and not system:
            raise ApiError("Unknown affected_system.", errors={"affected_system": ["Unknown or hidden system."]})
        if ticket.affected_system_id != (system.pk if system else None):
            ticket.affected_system = system
            update_fields.append("affected_system")
    return update_fields


def _apply_case_status_payload(ticket: Ticket, payload: dict[str, Any], agent_token: OperationsAgentToken) -> bool:
    if "status" not in payload:
        return False
    new_status = str(payload.get("status", "")).strip()
    valid_statuses = {choice[0] for choice in TicketStatus.choices}
    if new_status not in valid_statuses:
        raise ApiError("Unsupported lifecycle status.", errors={"status": ["Unsupported lifecycle status."]})
    if not agent_token.user.is_staff:
        raise ApiError("Status updates require a staff/operator service account.", status=403)
    if new_status == ticket.status:
        return False
    note = str(payload.get("note", "")).strip()
    try:
        transition_ticket_status(ticket, status=new_status, actor=agent_token.user, note=note)
    except TicketOperationError as exc:
        raise ApiError(str(exc)) from exc
    return True


def _case_event_payload(payload: dict[str, Any]) -> dict[str, Any]:
    event_type = str(payload.get("event_type", "")).strip()
    source = str(payload.get("source", "open-response-center")).strip()
    summary = str(payload.get("summary", "")).strip()
    severity = str(payload.get("severity", CaseEventSeverity.INFO)).strip()
    metadata = payload.get("metadata", {})
    occurred_at = payload.get("occurred_at")
    if not event_type:
        raise ApiError("event_type is required.", errors={"event_type": ["Required."]})
    if not source:
        raise ApiError("source is required.", errors={"source": ["Required."]})
    if slugify(event_type) != event_type:
        raise ApiError("event_type must be a slug.", errors={"event_type": ["Use a slug value."]})
    if slugify(source) != source:
        raise ApiError("source must be a slug.", errors={"source": ["Use a slug value."]})
    if not summary:
        raise ApiError("summary is required.", errors={"summary": ["Required."]})
    if severity not in {choice[0] for choice in CaseEventSeverity.choices}:
        raise ApiError("Unsupported severity.", errors={"severity": ["Unsupported severity."]})
    if not isinstance(metadata, dict):
        raise ApiError("metadata must be an object.", errors={"metadata": ["Must be an object."]})
    parsed_occurred_at = None
    if occurred_at:
        parsed_occurred_at = parse_datetime(str(occurred_at))
        if not parsed_occurred_at:
            raise ApiError("occurred_at must be an ISO datetime.", errors={"occurred_at": ["Invalid datetime."]})
    return {
        "event_type": event_type,
        "source": source,
        "summary": summary,
        "severity": severity,
        "metadata": metadata,
        "occurred_at": parsed_occurred_at,
    }


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
    ticket = create_ticket_from_form(form, reporter=agent_token.user)
    return JsonResponse({"ticket": _serialize_ticket(ticket)}, status=201)


@require_http_methods(["POST"])
@_api_view(OperationsAgentScope.CASES_CREATE)
def api_case_upsert(request: HttpRequest, agent_token: OperationsAgentToken) -> JsonResponse:
    payload = _parse_json(request)
    reference_data = _external_reference_data(payload)
    reference = (
        ExternalReference.objects.select_related("ticket")
        .filter(provider=reference_data["provider"], external_id=reference_data["external_id"])
        .first()
    )
    created = reference is None
    if reference:
        ticket = _get_api_case(agent_token, reference.ticket_id)
        update_fields = _update_ticket_from_case_payload(ticket, payload)
        if update_fields:
            ticket.save()
        status_changed = _apply_case_status_payload(ticket, payload, agent_token)
        if reference.metadata != reference_data["metadata"]:
            reference.metadata = reference_data["metadata"]
            reference.save(update_fields=["metadata", "updated_at"])
        if status_changed:
            ticket.refresh_from_db()
    else:
        form = TicketCreateForm(_ticket_create_data(payload), user=agent_token.user)
        if not form.is_valid():
            raise ApiError("Case payload is invalid.", errors=_field_errors(form))
        ticket = create_ticket_from_form(form, reporter=agent_token.user)
        reference = ExternalReference.objects.create(ticket=ticket, **reference_data)
        _apply_case_status_payload(ticket, payload, agent_token)

    return JsonResponse(
        {
            "created": created,
            "case": _serialize_case(ticket),
            "external_reference": _serialize_external_reference(reference),
        },
        status=201 if created else 200,
    )


@csrf_exempt
@require_http_methods(["GET", "PATCH"])
def api_case_detail(request: HttpRequest, pk: int) -> JsonResponse:
    scope = OperationsAgentScope.CASES_READ if request.method == "GET" else OperationsAgentScope.CASES_UPDATE
    agent_token = _authenticate(request, scope)
    if isinstance(agent_token, JsonResponse):
        return agent_token
    try:
        ticket = _get_api_case(agent_token, pk)
        if request.method == "PATCH":
            payload = _parse_json(request)
            update_fields = _update_ticket_from_case_payload(ticket, payload)
            if update_fields:
                ticket.save()
            _apply_case_status_payload(ticket, payload, agent_token)
            ticket.refresh_from_db()
        return JsonResponse({"case": _serialize_case(ticket)})
    except ApiError as exc:
        return _json_error(str(exc), status=exc.status, errors=exc.errors)


@require_http_methods(["GET"])
@_api_view(OperationsAgentScope.CASES_READ)
def api_case_external_detail(
    request: HttpRequest,
    agent_token: OperationsAgentToken,
    provider: str,
    external_id: str,
) -> JsonResponse:
    reference = ExternalReference.objects.filter(provider=provider, external_id=external_id).first()
    if not reference:
        raise ApiError("Case not found.", status=404)
    ticket = _get_api_case(agent_token, reference.ticket_id)
    return JsonResponse(
        {
            "case": _serialize_case(ticket),
            "external_reference": _serialize_external_reference(reference),
        }
    )


@require_http_methods(["POST"])
@_api_view(OperationsAgentScope.CASES_NOTE)
def api_case_note(request: HttpRequest, agent_token: OperationsAgentToken, pk: int) -> JsonResponse:
    ticket = _get_api_case(agent_token, pk)
    payload = _parse_json(request)
    form = MessageForm(payload)
    if not form.is_valid():
        raise ApiError("Note payload is invalid.", errors=_field_errors(form))
    message = add_ticket_message(
        ticket,
        author=agent_token.user,
        body=form.cleaned_data["body"],
        is_operator_note=bool(agent_token.user.is_staff and payload.get("is_operator_note")),
        notification_body=f"{agent_token.user} wrote via case API:\n\n{form.cleaned_data['body']}",
    )
    return JsonResponse({"message": _serialize_message(message), "case": _serialize_case(ticket)}, status=201)


@require_http_methods(["POST"])
@_api_view(OperationsAgentScope.CASES_EVENT)
def api_case_event(request: HttpRequest, agent_token: OperationsAgentToken, pk: int) -> JsonResponse:
    ticket = _get_api_case(agent_token, pk)
    payload = _parse_json(request)
    event_data = _case_event_payload(payload)
    reference = None
    reference_payload = payload.get("external_reference")
    if isinstance(reference_payload, dict):
        reference_data = _external_reference_data({"external_reference": reference_payload})
        reference = ExternalReference.objects.filter(
            provider=reference_data["provider"],
            external_id=reference_data["external_id"],
            ticket=ticket,
        ).first()
        if not reference:
            raise ApiError("External reference is not linked to this case.", status=404)
    event = record_case_event(
        ticket=ticket,
        actor=agent_token.user,
        external_reference=reference,
        **event_data,
    )
    fresh_ticket = _get_api_case(agent_token, ticket.pk)
    return JsonResponse({"event": _serialize_case_event(event), "case": _serialize_case(fresh_ticket)}, status=201)


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
    message = add_ticket_message(
        ticket,
        author=agent_token.user,
        body=form.cleaned_data["body"],
        is_operator_note=bool(agent_token.user.is_staff and payload.get("is_operator_note")),
        notification_body=f"{agent_token.user} wrote via operations-agent API:\n\n{form.cleaned_data['body']}",
    )
    return JsonResponse({"message": _serialize_message(message)}, status=201)


@require_http_methods(["POST"])
@_api_view(OperationsAgentScope.TICKETS_UPDATE)
def api_ticket_update(request: HttpRequest, agent_token: OperationsAgentToken, pk: int) -> JsonResponse:
    staff_error = _require_staff(agent_token)
    if staff_error:
        return staff_error
    ticket = _get_api_ticket(agent_token, pk)
    payload = _parse_json(request)
    form = OperatorUpdateForm(_operator_update_data(payload, ticket), instance=ticket)
    if not form.is_valid():
        raise ApiError("Ticket update payload is invalid.", errors=_field_errors(form))
    try:
        result = update_operator_fields_from_form(ticket, form=form, actor=agent_token.user)
    except TicketOperationError as exc:
        raise ApiError(str(exc)) from exc
    return JsonResponse({"ticket": _serialize_ticket(result.ticket)})


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
        result = create_operational_incident_from_ticket(
            ticket=ticket,
            actor=agent_token.user,
            classification=form.cleaned_data,
        )
    except TicketOperationError as exc:
        raise ApiError(str(exc)) from exc
    return JsonResponse(
        {
            "created": result.created,
            "incident": _serialize_incident(result.incident),
            "ticket": _serialize_ticket(result.incident.ticket),
        },
        status=201 if result.created else 200,
    )
