from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.db.models import Q
from django.http import FileResponse, Http404, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.text import slugify

from .forms import (
    AttachmentUploadForm,
    IncidentClassificationForm,
    InternalNoteForm,
    KnowledgeBaseArticleForm,
    MessageForm,
    NotificationPreferenceForm,
    OperatorUpdateForm,
    TicketKnowledgeBaseLinkForm,
    TicketCreateForm,
)
from .incident_adapters import OpenClawWorkspaceIncidentAdapter
from .models import (
    Attachment,
    KnowledgeBaseArticle,
    KnowledgeBaseAudience,
    NotificationPreference,
    Ticket,
    TicketKnowledgeBaseLink,
    TicketMessage,
    TicketStatus,
    TicketWorkflowChecklistItem,
)
from .notifications import notify_ticket_watchers


def _visible_tickets(user):
    queryset = Ticket.objects.select_related("affected_system", "reporter", "operator")
    if user.is_staff:
        return queryset.all()
    return queryset.filter(reporter=user)


def _get_visible_ticket(user, pk: int) -> Ticket:
    ticket = get_object_or_404(
        Ticket.objects.select_related(
            "affected_system", "department", "workflow_template", "reporter", "operator"
        ).prefetch_related(
            "attachments",
            "lifecycle_events",
            "operational_incidents",
            "workflow_items",
        ),
        pk=pk,
    )
    if not ticket.can_be_viewed_by(user):
        raise Http404
    return ticket


def _visible_knowledge_links(ticket: Ticket, user):
    queryset = ticket.knowledge_base_links.select_related("article", "linked_by").prefetch_related("article__systems")
    if user.is_staff:
        return queryset
    return queryset.filter(article__is_published=True, article__audience=KnowledgeBaseAudience.ALL_INTERNAL)


def _is_operator(user):
    return user.is_staff


@login_required
def ticket_list(request):
    tickets = _visible_tickets(request.user)
    status = request.GET.get("status")
    if status:
        tickets = tickets.filter(status=status)
    return render(request, "tickets/ticket_list.html", {"tickets": tickets, "status": status})


@user_passes_test(_is_operator)
def ticket_board(request):
    tickets = list(
        Ticket.objects.select_related(
            "affected_system",
            "department",
            "reporter",
            "operator",
            "workflow_template",
        ).order_by("status", "-updated_at", "-created_at")
    )
    tickets_by_status = {}
    for ticket in tickets:
        tickets_by_status.setdefault(ticket.status, []).append(ticket)
    board_columns = [
        {
            "status": status,
            "label": label,
            "tickets": tickets_by_status.get(status, []),
        }
        for status, label in TicketStatus.choices
    ]
    return render(request, "tickets/ticket_board.html", {"board_columns": board_columns})


@login_required
def ticket_create(request):
    if request.method == "POST":
        form = TicketCreateForm(request.POST, user=request.user)
        attachment_form = AttachmentUploadForm(request.POST, request.FILES)
        if form.is_valid() and attachment_form.is_valid():
            ticket = form.save(commit=False)
            ticket.reporter = request.user
            ticket.save()
            ticket.generate_workflow_checklist()
            TicketMessage.objects.create(ticket=ticket, author=request.user, body=ticket.description)
            uploaded_file = attachment_form.cleaned_data.get("file")
            if uploaded_file:
                Attachment.objects.create(
                    ticket=ticket,
                    uploaded_by=request.user,
                    file=uploaded_file,
                    original_name=uploaded_file.name,
                    content_type=getattr(uploaded_file, "content_type", ""),
                    size_bytes=uploaded_file.size,
                )
            NotificationPreference.objects.get_or_create(user=request.user)
            messages.success(request, "Ticket submitted.")
            return redirect("ticket-detail", pk=ticket.pk)
    else:
        form = TicketCreateForm(user=request.user)
        attachment_form = AttachmentUploadForm()
    return render(
        request,
        "tickets/ticket_form.html",
        {"form": form, "attachment_form": attachment_form},
    )


@login_required
def notification_preferences(request):
    preference, _ = NotificationPreference.objects.get_or_create(user=request.user)
    if request.method == "POST":
        form = NotificationPreferenceForm(request.POST, instance=preference)
        if form.is_valid():
            form.save()
            messages.success(request, "Email preferences saved.")
            return redirect("notification-preferences")
    else:
        form = NotificationPreferenceForm(instance=preference)
    return render(request, "tickets/notification_preferences.html", {"form": form})


@login_required
def ticket_detail(request, pk: int):
    ticket = _get_visible_ticket(request.user, pk)
    visible_messages = ticket.messages.select_related("author")
    if not request.user.is_staff:
        visible_messages = visible_messages.filter(is_operator_note=False)
    knowledge_links = _visible_knowledge_links(ticket, request.user)

    return render(
        request,
        "tickets/ticket_detail.html",
        {
            "ticket": ticket,
            "messages": visible_messages,
            "knowledge_links": knowledge_links,
            "knowledge_link_form": TicketKnowledgeBaseLinkForm(user=request.user) if request.user.is_staff else None,
            "message_form": MessageForm(),
            "internal_note_form": InternalNoteForm() if request.user.is_staff else None,
            "attachment_form": AttachmentUploadForm(),
            "operator_form": OperatorUpdateForm(instance=ticket) if request.user.is_staff else None,
            "incident_form": IncidentClassificationForm() if request.user.is_staff else None,
        },
    )


@login_required
def add_message(request, pk: int):
    ticket = _get_visible_ticket(request.user, pk)
    if request.method != "POST":
        return redirect("ticket-detail", pk=ticket.pk)
    form = MessageForm(request.POST)
    if form.is_valid():
        message = form.save(commit=False)
        message.ticket = ticket
        message.author = request.user
        message.is_operator_note = request.user.is_staff and request.POST.get("is_operator_note") == "1"
        message.save()
        if message.is_operator_note:
            messages.success(request, "Internal note added.")
        else:
            if request.user.is_staff:
                ticket.record_first_response()
            notify_ticket_watchers(
                ticket,
                f"New message on Open Response Center ticket #{ticket.pk}",
                f"{request.user} wrote:\n\n{message.body}\n\n{request.build_absolute_uri(ticket.get_absolute_url())}",
                event="thread",
                exclude_user_id=request.user.id,
            )
            messages.success(request, "Reply added.")
    return redirect("ticket-detail", pk=ticket.pk)


@login_required
def add_attachment(request, pk: int):
    ticket = _get_visible_ticket(request.user, pk)
    if request.method != "POST":
        return redirect("ticket-detail", pk=ticket.pk)
    form = AttachmentUploadForm(request.POST, request.FILES)
    if form.is_valid():
        uploaded_file = form.cleaned_data["file"]
        Attachment.objects.create(
            ticket=ticket,
            uploaded_by=request.user,
            file=uploaded_file,
            original_name=uploaded_file.name,
            content_type=getattr(uploaded_file, "content_type", ""),
            size_bytes=uploaded_file.size,
        )
        messages.success(request, "Attachment uploaded.")
    else:
        messages.error(request, "Attachment was not accepted.")
    return redirect("ticket-detail", pk=ticket.pk)


@login_required
def download_attachment(request, pk: int):
    attachment = get_object_or_404(Attachment.objects.select_related("ticket"), pk=pk)
    if not attachment.ticket.can_be_viewed_by(request.user):
        return HttpResponseForbidden("You cannot access this attachment.")
    return FileResponse(
        attachment.file.open("rb"),
        as_attachment=True,
        filename=attachment.original_name,
    )


@login_required
def knowledge_base_list(request):
    articles = KnowledgeBaseArticle.visible_to(request.user)
    query = request.GET.get("q", "").strip()
    if query:
        articles = articles.filter(
            Q(title__icontains=query)
            | Q(summary__icontains=query)
            | Q(body__icontains=query)
            | Q(tags__icontains=query)
            | Q(systems__name__icontains=query)
        ).distinct()
    return render(
        request,
        "tickets/knowledge_base_list.html",
        {"articles": articles, "query": query},
    )


@login_required
def knowledge_base_detail(request, slug: str):
    article = get_object_or_404(
        KnowledgeBaseArticle.objects.prefetch_related("systems").select_related("created_by", "updated_by"),
        slug=slug,
    )
    if not article.can_be_viewed_by(request.user):
        raise Http404
    return render(request, "tickets/knowledge_base_detail.html", {"article": article})


@user_passes_test(_is_operator)
def knowledge_base_create(request):
    if request.method == "POST":
        form = KnowledgeBaseArticleForm(request.POST)
        if form.is_valid():
            article = form.save(commit=False)
            article.created_by = request.user
            article.updated_by = request.user
            article.save()
            form.save_m2m()
            messages.success(request, "Knowledge article saved.")
            return redirect(article.get_absolute_url())
    else:
        form = KnowledgeBaseArticleForm()
    return render(request, "tickets/knowledge_base_form.html", {"form": form})


@user_passes_test(_is_operator)
def operator_update(request, pk: int):
    ticket = get_object_or_404(Ticket, pk=pk)
    if request.method != "POST":
        return redirect("ticket-detail", pk=ticket.pk)
    old_status = ticket.status
    old_workflow_template_id = ticket.workflow_template_id
    form = OperatorUpdateForm(request.POST, instance=ticket)
    if form.is_valid():
        updated_ticket = form.save(commit=False)
        new_status = form.cleaned_data["status"]
        note = form.cleaned_data.get("note", "")
        updated_ticket.status = old_status
        updated_ticket.save()
        if updated_ticket.workflow_template_id != old_workflow_template_id:
            created_count = updated_ticket.generate_workflow_checklist()
            if created_count:
                messages.info(request, f"Added {created_count} workflow checklist item(s).")
        if old_status != new_status:
            if new_status == TicketStatus.CLOSED and updated_ticket.has_blocking_workflow_items():
                messages.error(request, "Complete blocking workflow checklist items before closing this ticket.")
                return redirect("ticket-detail", pk=ticket.pk)
            updated_ticket.transition_to(status=new_status, actor=request.user, note=note)
            notify_ticket_watchers(
                updated_ticket,
                f"Open Response Center ticket #{updated_ticket.pk} moved to {updated_ticket.get_status_display()}",
                note or f"Status changed from {old_status} to {new_status}.",
                event="status",
                exclude_user_id=request.user.id,
            )
        messages.success(request, "Operator fields updated.")
    return redirect("ticket-detail", pk=ticket.pk)


@user_passes_test(_is_operator)
def update_workflow_checklist(request, pk: int):
    ticket = get_object_or_404(Ticket.objects.prefetch_related("workflow_items"), pk=pk)
    if request.method != "POST":
        return redirect("ticket-detail", pk=ticket.pk)
    done_ids = {int(item_id) for item_id in request.POST.getlist("done_items") if item_id.isdigit()}
    for item in TicketWorkflowChecklistItem.objects.filter(ticket=ticket):
        item.set_done(is_done=item.pk in done_ids, actor=request.user)
    messages.success(request, "Workflow checklist updated.")
    return redirect("ticket-detail", pk=ticket.pk)


@user_passes_test(_is_operator)
def link_knowledge_base_article(request, pk: int):
    ticket = get_object_or_404(Ticket, pk=pk)
    if request.method != "POST":
        return redirect("ticket-detail", pk=ticket.pk)
    form = TicketKnowledgeBaseLinkForm(request.POST, user=request.user)
    if form.is_valid():
        article = form.cleaned_data["article"]
        link, created = TicketKnowledgeBaseLink.objects.get_or_create(
            ticket=ticket,
            article=article,
            defaults={
                "note": form.cleaned_data.get("note", ""),
                "linked_by": request.user,
            },
        )
        if created:
            messages.success(request, "Knowledge article linked.")
        else:
            link.note = form.cleaned_data.get("note", "")
            link.linked_by = request.user
            link.save(update_fields=["note", "linked_by"])
            messages.info(request, "Knowledge article link updated.")
    else:
        messages.error(request, "Knowledge article link was not accepted.")
    return redirect("ticket-detail", pk=ticket.pk)


@user_passes_test(_is_operator)
def draft_knowledge_base_from_ticket(request, pk: int):
    ticket = get_object_or_404(Ticket.objects.select_related("affected_system", "reporter"), pk=pk)
    if request.method != "POST":
        return redirect("ticket-detail", pk=ticket.pk)
    slug = f"ticket-{ticket.pk}-{slugify(ticket.title)[:160]}"
    article, created = KnowledgeBaseArticle.objects.get_or_create(
        slug=slug,
        defaults={
            "title": f"Runbook: {ticket.title}",
            "summary": ticket.issue_summary or ticket.title,
            "body": (
                f"# {ticket.title}\n\n"
                f"## Symptom\n\n{ticket.issue_summary or ticket.description}\n\n"
                f"## Reproduction\n\n{ticket.reproduction_steps or '-'}\n\n"
                f"## Expected\n\n{ticket.expected_outcome or '-'}\n\n"
                f"## Actual\n\n{ticket.actual_outcome or '-'}\n\n"
                "## Operator Notes\n\nAdd triage, mitigation, and verification steps here.\n"
            ),
            "audience": KnowledgeBaseAudience.OPERATORS,
            "tags": "draft, ticket-derived",
            "is_published": False,
            "created_by": request.user,
            "updated_by": request.user,
        },
    )
    if ticket.affected_system:
        article.systems.add(ticket.affected_system)
    TicketKnowledgeBaseLink.objects.get_or_create(
        ticket=ticket,
        article=article,
        defaults={"note": "Drafted from this ticket.", "linked_by": request.user},
    )
    messages.success(request, "Knowledge article draft created." if created else "Knowledge article draft already exists.")
    return redirect(article.get_absolute_url())


@user_passes_test(_is_operator)
def create_operational_incident(request, pk: int):
    ticket = get_object_or_404(Ticket, pk=pk)
    if request.method != "POST":
        return redirect("ticket-detail", pk=ticket.pk)
    form = IncidentClassificationForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Incident classification was not accepted.")
        return redirect("ticket-detail", pk=ticket.pk)
    result = OpenClawWorkspaceIncidentAdapter().create_from_ticket(
        ticket=ticket,
        actor=request.user,
        classification=form.cleaned_data,
    )
    if result.created:
        messages.success(request, f"Operational incident {result.incident.reference} created and linked.")
    else:
        messages.info(request, f"Operational incident {result.incident.reference} is already linked.")
    return redirect("ticket-detail", pk=ticket.pk)
