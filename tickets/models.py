from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
import secrets
from datetime import timedelta
from uuid import uuid4

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.core.validators import FileExtensionValidator
from django.db import models
from django.db.models import Q
from django.urls import reverse
from django.utils.text import slugify
from django.utils import timezone


User = get_user_model()


class OperationsAgentScope(models.TextChoices):
    TICKETS_CREATE = "tickets:create", "Create tickets"
    TICKETS_READ = "tickets:read", "Read visible tickets"
    TICKETS_MESSAGE = "tickets:message", "Add ticket messages"
    TICKETS_UPDATE = "tickets:update", "Update ticket lifecycle fields"
    CASES_CREATE = "cases:create", "Create or upsert cases"
    CASES_READ = "cases:read", "Read visible cases"
    CASES_UPDATE = "cases:update", "Update cases"
    CASES_NOTE = "cases:note", "Add case notes"
    CASES_EVENT = "cases:event", "Add case events"
    INCIDENTS_PROMOTE = "incidents:promote", "Promote tickets to operational incidents"


class OperationsAgentToken(models.Model):
    name = models.CharField(max_length=120, unique=True)
    user = models.ForeignKey(User, on_delete=models.PROTECT, related_name="operations_agent_tokens")
    prefix = models.CharField(max_length=16, unique=True)
    token_hash = models.CharField(max_length=64, unique=True)
    scopes = models.JSONField(default=list, blank=True)
    is_active = models.BooleanField(default=True)
    last_used_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name

    @classmethod
    def issue(cls, *, name: str, user: User, scopes: list[str]) -> tuple["OperationsAgentToken", str]:
        prefix = secrets.token_hex(6)
        secret = secrets.token_urlsafe(32)
        raw_token = f"orc_agent_{prefix}_{secret}"
        agent_token = cls.objects.create(
            name=name,
            user=user,
            prefix=prefix,
            token_hash=cls.hash_token(raw_token),
            scopes=scopes,
        )
        return agent_token, raw_token

    @staticmethod
    def hash_token(raw_token: str) -> str:
        return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    @classmethod
    def prefix_from_raw_token(cls, raw_token: str) -> str:
        parts = raw_token.split("_", 3)
        if len(parts) != 4 or parts[:2] != ["orc", "agent"]:
            return ""
        return parts[2]

    def token_matches(self, raw_token: str) -> bool:
        return hmac.compare_digest(self.token_hash, self.hash_token(raw_token))

    def has_scope(self, scope: str) -> bool:
        return scope in set(self.scopes or [])


class TicketStatus(models.TextChoices):
    RECEIVED = "received", "Received"
    TRIAGED = "triaged", "Triaged"
    IN_PROGRESS = "in_progress", "In progress"
    WAITING_ON_REPORTER = "waiting_on_reporter", "Waiting on reporter"
    WAITING_ON_VENDOR = "waiting_on_vendor", "Waiting on vendor/external dependency"
    FIXED = "fixed", "Fixed"
    VERIFIED = "verified", "Verified"
    CLOSED = "closed", "Closed"


class ImpactLevel(models.TextChoices):
    LOW = "low", "Low"
    MEDIUM = "medium", "Medium"
    HIGH = "high", "High"
    CRITICAL = "critical", "Critical"


SLA_DEFAULT_WINDOWS = {
    ImpactLevel.CRITICAL: (15, 240),
    ImpactLevel.HIGH: (60, 480),
    ImpactLevel.MEDIUM: (240, 1440),
    ImpactLevel.LOW: (1440, 4320),
}

SLA_RESPONSE_STATUSES = {
    TicketStatus.TRIAGED,
    TicketStatus.IN_PROGRESS,
    TicketStatus.WAITING_ON_REPORTER,
    TicketStatus.WAITING_ON_VENDOR,
    TicketStatus.FIXED,
    TicketStatus.VERIFIED,
    TicketStatus.CLOSED,
}

SLA_RESOLVED_STATUSES = {
    TicketStatus.FIXED,
    TicketStatus.VERIFIED,
    TicketStatus.CLOSED,
}


class SlaPolicy(models.Model):
    impact = models.CharField(max_length=20, choices=ImpactLevel.choices, unique=True)
    response_minutes = models.PositiveIntegerField()
    resolution_minutes = models.PositiveIntegerField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["impact"]
        verbose_name = "SLA policy"
        verbose_name_plural = "SLA policies"

    def __str__(self) -> str:
        return f"{self.get_impact_display()}: response {self.response_minutes}m, resolution {self.resolution_minutes}m"

    @classmethod
    def window_for_impact(cls, impact: str) -> tuple[int, int]:
        policy = cls.objects.filter(impact=impact, is_active=True).first()
        if policy:
            return policy.response_minutes, policy.resolution_minutes
        return SLA_DEFAULT_WINDOWS.get(impact, SLA_DEFAULT_WINDOWS[ImpactLevel.MEDIUM])


class Department(models.Model):
    name = models.CharField(max_length=120, unique=True)
    slug = models.SlugField(max_length=140, unique=True)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    operator_groups = models.ManyToManyField(
        Group,
        blank=True,
        related_name="departments",
        help_text="Groups responsible for this department queue.",
    )

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name


class DepartmentIntakeFieldType(models.TextChoices):
    TEXT = "text", "Short text"
    TEXTAREA = "textarea", "Long text"
    URL = "url", "URL"
    SELECT = "select", "Select"
    CHECKBOX = "checkbox", "Checkbox"


class DepartmentIntakeField(models.Model):
    department = models.ForeignKey(Department, on_delete=models.CASCADE, related_name="intake_fields")
    label = models.CharField(max_length=140)
    slug = models.SlugField(max_length=160)
    help_text = models.CharField(max_length=240, blank=True)
    field_type = models.CharField(
        max_length=20,
        choices=DepartmentIntakeFieldType.choices,
        default=DepartmentIntakeFieldType.TEXT,
    )
    choices = models.TextField(blank=True, help_text="One option per line for select fields.")
    is_required = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    sort_order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["sort_order", "label"]
        constraints = [
            models.UniqueConstraint(fields=["department", "slug"], name="unique_department_intake_field"),
        ]

    def __str__(self) -> str:
        return f"{self.department}: {self.label}"

    def choice_pairs(self) -> list[tuple[str, str]]:
        return [(choice.strip(), choice.strip()) for choice in self.choices.splitlines() if choice.strip()]


class System(models.Model):
    name = models.CharField(max_length=120, unique=True)
    slug = models.SlugField(max_length=140, unique=True)
    description = models.TextField(blank=True)
    default_department = models.ForeignKey(
        Department,
        blank=True,
        null=True,
        on_delete=models.SET_NULL,
        related_name="systems",
    )
    default_workflow_template = models.ForeignKey(
        "WorkflowTemplate",
        blank=True,
        null=True,
        on_delete=models.SET_NULL,
        related_name="systems",
    )
    is_active = models.BooleanField(default=True)
    visible_to_users = models.ManyToManyField(
        User,
        blank=True,
        related_name="visible_systems",
        help_text="Leave users and groups empty to show this system to all reporters.",
    )
    visible_to_groups = models.ManyToManyField(
        Group,
        blank=True,
        related_name="visible_systems",
        help_text="Leave users and groups empty to show this system to all reporters.",
    )

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name

    @classmethod
    def visible_to(cls, user: User):
        queryset = cls.objects.filter(is_active=True)
        if not user.is_authenticated:
            return queryset.none()
        if user.is_staff:
            return queryset
        return (
            queryset.filter(
                Q(visible_to_users=user)
                | Q(visible_to_groups__user=user)
                | (Q(visible_to_users__isnull=True) & Q(visible_to_groups__isnull=True))
            )
            .distinct()
            .order_by("name")
        )


class WorkflowTemplate(models.Model):
    name = models.CharField(max_length=120)
    department = models.ForeignKey(Department, on_delete=models.CASCADE, related_name="workflow_templates")
    summary = models.TextField(blank=True)
    default_impact = models.CharField(
        max_length=20,
        choices=ImpactLevel.choices,
        blank=True,
        help_text="Optional impact applied when reporters leave the default medium impact unchanged.",
    )
    incident_promotion_expected = models.BooleanField(
        default=False,
        help_text="Signals that operators should normally promote tickets in this workflow to operational incidents.",
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["department__name", "name"]
        constraints = [
            models.UniqueConstraint(fields=["department", "name"], name="unique_department_workflow_template"),
        ]

    def __str__(self) -> str:
        return f"{self.department}: {self.name}"


class WorkflowChecklistItemTemplate(models.Model):
    workflow_template = models.ForeignKey(
        WorkflowTemplate,
        on_delete=models.CASCADE,
        related_name="checklist_item_templates",
    )
    title = models.CharField(max_length=180)
    description = models.TextField(blank=True)
    blocks_closure = models.BooleanField(default=True)
    sort_order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["sort_order", "title"]

    def __str__(self) -> str:
        return self.title


class KnowledgeBaseAudience(models.TextChoices):
    ALL_INTERNAL = "all_internal", "All internal users"
    OPERATORS = "operators", "Operators only"


class KnowledgeBaseArticle(models.Model):
    title = models.CharField(max_length=180)
    slug = models.SlugField(max_length=200, unique=True, blank=True)
    summary = models.TextField(blank=True)
    body = models.TextField()
    audience = models.CharField(
        max_length=30,
        choices=KnowledgeBaseAudience.choices,
        default=KnowledgeBaseAudience.ALL_INTERNAL,
    )
    systems = models.ManyToManyField(System, blank=True, related_name="knowledge_base_articles")
    tags = models.CharField(max_length=240, blank=True, help_text="Comma-separated internal tags.")
    is_published = models.BooleanField(default=False)
    created_by = models.ForeignKey(
        User,
        blank=True,
        null=True,
        on_delete=models.SET_NULL,
        related_name="created_knowledge_base_articles",
    )
    updated_by = models.ForeignKey(
        User,
        blank=True,
        null=True,
        on_delete=models.SET_NULL,
        related_name="updated_knowledge_base_articles",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["title"]

    def __str__(self) -> str:
        return self.title

    def get_absolute_url(self) -> str:
        return reverse("knowledge-base-detail", kwargs={"slug": self.slug})

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.title)[:200]
        super().save(*args, **kwargs)

    def can_be_viewed_by(self, user: User) -> bool:
        if not user.is_authenticated:
            return False
        if user.is_staff:
            return True
        return bool(self.is_published and self.audience == KnowledgeBaseAudience.ALL_INTERNAL)

    @classmethod
    def visible_to(cls, user: User):
        queryset = cls.objects.prefetch_related("systems").select_related("created_by", "updated_by")
        if not user.is_authenticated:
            return queryset.none()
        if user.is_staff:
            return queryset
        return queryset.filter(is_published=True, audience=KnowledgeBaseAudience.ALL_INTERNAL)


class Ticket(models.Model):
    title = models.CharField(max_length=180)
    description = models.TextField()
    issue_summary = models.TextField(blank=True)
    reproduction_steps = models.TextField(blank=True)
    expected_outcome = models.TextField(blank=True)
    actual_outcome = models.TextField(blank=True)
    additional_context = models.TextField(blank=True)
    intake_field_values = models.JSONField(blank=True, default=dict)
    affected_system = models.ForeignKey(
        System,
        blank=True,
        null=True,
        on_delete=models.SET_NULL,
        related_name="tickets",
    )
    department = models.ForeignKey(
        Department,
        blank=True,
        null=True,
        on_delete=models.SET_NULL,
        related_name="tickets",
    )
    workflow_template = models.ForeignKey(
        WorkflowTemplate,
        blank=True,
        null=True,
        on_delete=models.SET_NULL,
        related_name="tickets",
    )
    impact = models.CharField(
        max_length=20,
        choices=ImpactLevel.choices,
        default=ImpactLevel.MEDIUM,
    )
    status = models.CharField(
        max_length=40,
        choices=TicketStatus.choices,
        default=TicketStatus.RECEIVED,
    )
    board_position = models.PositiveIntegerField(
        default=0,
        help_text="Operator board ordering within the ticket's current lifecycle status.",
    )
    reporter = models.ForeignKey(User, on_delete=models.PROTECT, related_name="reported_tickets")
    operator = models.ForeignKey(
        User,
        blank=True,
        null=True,
        on_delete=models.SET_NULL,
        related_name="assigned_tickets",
    )
    incident_reference = models.CharField(
        max_length=40,
        blank=True,
        help_text="Canonical workspace incident reference, for example INC-2026-0001.",
    )
    engineering_reference = models.CharField(
        max_length=200,
        blank=True,
        help_text="Optional issue, PR, or tracker link/reference.",
    )
    first_response_at = models.DateTimeField(blank=True, null=True)
    resolved_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at", "-created_at"]
        indexes = [
            models.Index(fields=["status", "board_position", "-updated_at"]),
            models.Index(fields=["reporter", "-updated_at"]),
        ]

    def __str__(self) -> str:
        return f"#{self.pk} {self.title}" if self.pk else self.title

    def get_absolute_url(self) -> str:
        return reverse("ticket-detail", kwargs={"pk": self.pk})

    def build_description(self) -> str:
        sections = [
            ("Summary of issue", self.issue_summary),
            ("Steps to reproduce", self.reproduction_steps),
            ("Expected outcome", self.expected_outcome),
            ("Actual outcome", self.actual_outcome),
            ("Additional context", self.additional_context),
        ]
        if self.intake_field_values:
            for field in self.intake_field_values.values():
                label = field.get("label", "").strip()
                value = field.get("display_value", field.get("value"))
                if label and str(value or "").strip():
                    sections.append((label, str(value).strip()))
        return "\n\n".join(f"{heading}:\n{body.strip()}" for heading, body in sections if body.strip())

    def save(self, *args, **kwargs):
        self.apply_workflow_defaults()
        structured_description = self.build_description()
        if structured_description:
            self.description = structured_description
        super().save(*args, **kwargs)

    def apply_workflow_defaults(self) -> None:
        is_new = self._state.adding or not self.pk
        if is_new and self.affected_system:
            if not self.department and self.affected_system.default_department:
                self.department = self.affected_system.default_department
            if not self.workflow_template and self.affected_system.default_workflow_template:
                self.workflow_template = self.affected_system.default_workflow_template
        if self.workflow_template and not self.department:
            self.department = self.workflow_template.department
        if is_new and self.department and not self.workflow_template:
            self.workflow_template = self.department.workflow_templates.filter(is_active=True).first()
        if is_new and self.workflow_template and self.workflow_template.default_impact and self.impact == ImpactLevel.MEDIUM:
            self.impact = self.workflow_template.default_impact

    def generate_workflow_checklist(self) -> int:
        if not self.pk or not self.workflow_template:
            return 0
        created_count = 0
        for template_item in self.workflow_template.checklist_item_templates.all():
            _, created = TicketWorkflowChecklistItem.objects.get_or_create(
                ticket=self,
                source_template=template_item,
                defaults={
                    "title": template_item.title,
                    "description": template_item.description,
                    "blocks_closure": template_item.blocks_closure,
                    "sort_order": template_item.sort_order,
                },
            )
            if created:
                created_count += 1
        return created_count

    def has_blocking_workflow_items(self) -> bool:
        return self.workflow_items.filter(blocks_closure=True, is_done=False).exists()

    @property
    def is_open(self) -> bool:
        return self.status != TicketStatus.CLOSED

    def can_be_viewed_by(self, user: User) -> bool:
        return bool(user.is_authenticated and (user.is_staff or self.reporter_id == user.id))

    @property
    def sla_response_due_at(self):
        response_minutes, _ = SlaPolicy.window_for_impact(self.impact)
        return self.created_at + timedelta(minutes=response_minutes)

    @property
    def sla_resolution_due_at(self):
        _, resolution_minutes = SlaPolicy.window_for_impact(self.impact)
        return self.created_at + timedelta(minutes=resolution_minutes)

    @property
    def sla_summary(self) -> dict[str, object]:
        response_minutes, resolution_minutes = SlaPolicy.window_for_impact(self.impact)
        response_due_at = self.created_at + timedelta(minutes=response_minutes)
        resolution_due_at = self.created_at + timedelta(minutes=resolution_minutes)
        response_state = self._sla_state_for(
            completed_at=self.first_response_at,
            due_at=response_due_at,
            window_minutes=response_minutes,
        )
        resolution_state = self._sla_state_for(
            completed_at=self.resolved_at,
            due_at=resolution_due_at,
            window_minutes=resolution_minutes,
        )
        combined_state = self._combined_sla_state(response_state, resolution_state)
        return {
            "state": combined_state,
            "response_state": response_state,
            "resolution_state": resolution_state,
            "state_label": self._sla_state_label(combined_state),
            "response_state_label": self._sla_state_label(response_state),
            "resolution_state_label": self._sla_state_label(resolution_state),
            "response_due_at": response_due_at,
            "resolution_due_at": resolution_due_at,
            "first_response_at": self.first_response_at,
            "resolved_at": self.resolved_at,
            "response_minutes": response_minutes,
            "resolution_minutes": resolution_minutes,
        }

    @property
    def sla_state(self) -> str:
        return str(self.sla_summary["state"])

    @property
    def sla_state_label(self) -> str:
        return str(self.sla_summary["state_label"])

    def record_first_response(self, when=None) -> None:
        if self.first_response_at:
            return
        self.first_response_at = when or timezone.now()
        self.save(update_fields=["first_response_at", "updated_at"])

    def _sla_state_for(self, *, completed_at, due_at, window_minutes: int) -> str:
        if completed_at:
            return "met" if completed_at <= due_at else "breached"
        now = timezone.now()
        if now > due_at:
            return "breached"
        at_risk_window = timedelta(minutes=max(15, int(window_minutes * 0.25)))
        if due_at - now <= at_risk_window:
            return "at_risk"
        return "on_track"

    def _combined_sla_state(self, response_state: str, resolution_state: str) -> str:
        states = {response_state, resolution_state}
        if "breached" in states:
            return "breached"
        if "at_risk" in states:
            return "at_risk"
        if states == {"met"}:
            return "met"
        return "on_track"

    def _sla_state_label(self, state: str) -> str:
        if state == "breached":
            return "Late"
        return state.replace("_", " ").title()

    def transition_to(self, *, status: str, actor: User, note: str = "") -> None:
        previous_status = self.status
        if previous_status == status:
            return
        now = timezone.now()
        self.status = status
        update_fields = ["status", "updated_at"]
        if not self.first_response_at and status in SLA_RESPONSE_STATUSES:
            self.first_response_at = now
            update_fields.append("first_response_at")
        if status in SLA_RESOLVED_STATUSES and not self.resolved_at:
            self.resolved_at = now
            update_fields.append("resolved_at")
        elif previous_status in SLA_RESOLVED_STATUSES and status not in SLA_RESOLVED_STATUSES and self.resolved_at:
            self.resolved_at = None
            update_fields.append("resolved_at")
        self.save(update_fields=update_fields)
        LifecycleEvent.objects.create(
            ticket=self,
            actor=actor,
            previous_status=previous_status,
            new_status=status,
            note=note,
        )


class TicketKnowledgeBaseLink(models.Model):
    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name="knowledge_base_links")
    article = models.ForeignKey(KnowledgeBaseArticle, on_delete=models.CASCADE, related_name="ticket_links")
    note = models.TextField(blank=True)
    linked_by = models.ForeignKey(User, on_delete=models.PROTECT, related_name="knowledge_base_links")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(fields=["ticket", "article"], name="unique_ticket_knowledge_base_article")
        ]

    def __str__(self) -> str:
        return f"{self.ticket} -> {self.article}"


class IncidentBackend(models.TextChoices):
    OPENCLAW_WORKSPACE = "openclaw_workspace", "OpenClaw workspace"


class IncidentScope(models.TextChoices):
    OPENCLAW_LOCAL = "openclaw-local", "OpenClaw local"
    OPENCLAW_REMOTE = "openclaw-remote", "OpenClaw remote"
    OWNED_SOFTWARE = "owned-software", "Owned software"
    OWNED_HARDWARE = "owned-hardware", "Owned hardware"
    EXTERNAL_SERVICE = "external-service", "External service"
    PERSONAL_MANUAL = "personal-manual", "Personal/manual"


class IncidentActionability(models.TextChoices):
    AUTO_FIX = "auto-fix", "Auto-fix"
    GUIDED_FIX = "guided-fix", "Guided fix"
    TRACKED_ONLY = "tracked-only", "Tracked only"


class IncidentAccessLevel(models.TextChoices):
    NONE = "none", "None"
    READ_ONLY = "read-only", "Read-only"
    LOCAL_SHELL = "local-shell", "Local shell"
    SSH = "ssh", "SSH"
    ADMIN = "admin", "Admin"
    PHYSICAL = "physical", "Physical"
    EXTERNAL_ACCOUNT = "external-account", "External account"


class IncidentExposure(models.TextChoices):
    NONE = "none", "None"
    INTERNAL = "internal", "Internal"
    PRIVATE_CHANNEL = "private-channel", "Private channel"
    PUBLIC = "public", "Public"
    USER_DATA = "user-data", "User data"
    CREDENTIAL = "credential", "Credential"


class IncidentRisk(models.TextChoices):
    LOW = "low", "Low"
    MEDIUM = "medium", "Medium"
    HIGH = "high", "High"
    CRITICAL = "critical", "Critical"


class IncidentPLevel(models.TextChoices):
    P0 = "P0", "P0"
    P1 = "P1", "P1"
    P2 = "P2", "P2"
    P3 = "P3", "P3"
    P4 = "P4", "P4"


class HumanInputRequired(models.TextChoices):
    NO = "no", "No"
    DECISION = "decision", "Decision"
    EXTERNAL_APPROVAL = "external approval", "External approval"
    FINAL_ACCEPTANCE = "final acceptance", "Final acceptance"


class OperationalIncident(models.Model):
    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name="operational_incidents")
    backend = models.CharField(
        max_length=40,
        choices=IncidentBackend.choices,
        default=IncidentBackend.OPENCLAW_WORKSPACE,
    )
    reference = models.CharField(max_length=120)
    title = models.CharField(max_length=220)
    status = models.CharField(max_length=40, default="intake")
    scope = models.CharField(max_length=40, choices=IncidentScope.choices, default=IncidentScope.OWNED_SOFTWARE)
    actionability = models.CharField(
        max_length=40,
        choices=IncidentActionability.choices,
        default=IncidentActionability.AUTO_FIX,
    )
    access_level = models.CharField(
        max_length=40,
        choices=IncidentAccessLevel.choices,
        default=IncidentAccessLevel.LOCAL_SHELL,
    )
    exposure = models.CharField(
        max_length=40,
        choices=IncidentExposure.choices,
        default=IncidentExposure.PRIVATE_CHANNEL,
    )
    risk = models.CharField(max_length=40, choices=IncidentRisk.choices, default=IncidentRisk.MEDIUM)
    p_level = models.CharField(max_length=2, choices=IncidentPLevel.choices, default=IncidentPLevel.P3)
    human_input_required = models.CharField(max_length=40, choices=HumanInputRequired.choices, default=HumanInputRequired.NO)
    classification_note = models.TextField(blank=True)
    path = models.CharField(max_length=500, blank=True)
    evidence_path = models.CharField(max_length=500, blank=True)
    created_by = models.ForeignKey(User, on_delete=models.PROTECT, related_name="created_operational_incidents")
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(fields=["backend", "reference"], name="unique_operational_incident_reference"),
            models.UniqueConstraint(fields=["ticket", "backend"], name="unique_ticket_incident_backend"),
        ]

    def __str__(self) -> str:
        return f"{self.reference} ({self.get_backend_display()})"


class ExternalReference(models.Model):
    provider = models.SlugField(max_length=80)
    external_id = models.CharField(max_length=240)
    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name="external_references")
    operational_incident = models.ForeignKey(
        OperationalIncident,
        blank=True,
        null=True,
        on_delete=models.SET_NULL,
        related_name="external_references",
    )
    metadata = models.JSONField(blank=True, default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["provider", "external_id"]
        constraints = [
            models.UniqueConstraint(fields=["provider", "external_id"], name="unique_external_reference"),
        ]
        indexes = [
            models.Index(fields=["provider", "external_id"]),
            models.Index(fields=["ticket", "provider"]),
        ]

    def __str__(self) -> str:
        return f"{self.provider}:{self.external_id}"


class CaseEventSeverity(models.TextChoices):
    INFO = "info", "Info"
    WARNING = "warning", "Warning"
    ERROR = "error", "Error"
    CRITICAL = "critical", "Critical"


class CaseEvent(models.Model):
    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name="case_events")
    external_reference = models.ForeignKey(
        ExternalReference,
        blank=True,
        null=True,
        on_delete=models.SET_NULL,
        related_name="case_events",
    )
    actor = models.ForeignKey(
        User,
        blank=True,
        null=True,
        on_delete=models.SET_NULL,
        related_name="case_events",
    )
    source = models.SlugField(max_length=80, default="open-response-center")
    event_type = models.SlugField(max_length=80)
    severity = models.CharField(max_length=20, choices=CaseEventSeverity.choices, default=CaseEventSeverity.INFO)
    summary = models.TextField()
    metadata = models.JSONField(blank=True, default=dict)
    occurred_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]
        indexes = [
            models.Index(fields=["ticket", "created_at"]),
            models.Index(fields=["source", "event_type"]),
        ]

    def __str__(self) -> str:
        return f"{self.ticket_id} {self.source}:{self.event_type}"


class TicketWorkflowChecklistItem(models.Model):
    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name="workflow_items")
    source_template = models.ForeignKey(
        WorkflowChecklistItemTemplate,
        blank=True,
        null=True,
        on_delete=models.SET_NULL,
        related_name="ticket_items",
    )
    title = models.CharField(max_length=180)
    description = models.TextField(blank=True)
    blocks_closure = models.BooleanField(default=True)
    is_done = models.BooleanField(default=False)
    completed_by = models.ForeignKey(
        User,
        blank=True,
        null=True,
        on_delete=models.SET_NULL,
        related_name="completed_workflow_items",
    )
    completed_at = models.DateTimeField(blank=True, null=True)
    sort_order = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["sort_order", "created_at"]
        constraints = [
            models.UniqueConstraint(fields=["ticket", "source_template"], name="unique_ticket_workflow_source_item"),
        ]

    def __str__(self) -> str:
        return self.title

    def set_done(self, *, is_done: bool, actor: User) -> None:
        if self.is_done == is_done:
            return
        self.is_done = is_done
        if is_done:
            self.completed_by = actor
            self.completed_at = timezone.now()
        else:
            self.completed_by = None
            self.completed_at = None
        self.save(update_fields=["is_done", "completed_by", "completed_at"])


class TicketMessage(models.Model):
    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name="messages")
    author = models.ForeignKey(User, on_delete=models.PROTECT, related_name="ticket_messages")
    body = models.TextField()
    is_operator_note = models.BooleanField(
        default=False,
        help_text="Internal operator note hidden from reporters.",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]

    def __str__(self) -> str:
        return f"Message on ticket #{self.ticket_id} by {self.author}"


def attachment_upload_path(instance: "Attachment", filename: str) -> str:
    suffix = Path(filename).suffix.lower()
    return f"tickets/{instance.ticket_id}/{uuid4().hex}{suffix}"


def validate_attachment_size(file_obj) -> None:
    max_bytes = 10 * 1024 * 1024
    if file_obj.size > max_bytes:
        raise ValidationError("Attachments must be 10 MiB or smaller.")


class Attachment(models.Model):
    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name="attachments")
    uploaded_by = models.ForeignKey(User, on_delete=models.PROTECT, related_name="ticket_attachments")
    file = models.FileField(
        upload_to=attachment_upload_path,
        validators=[
            validate_attachment_size,
            FileExtensionValidator(
                allowed_extensions=[
                    "txt",
                    "log",
                    "csv",
                    "json",
                    "png",
                    "jpg",
                    "jpeg",
                    "gif",
                    "webp",
                    "pdf",
                    "zip",
                ]
            ),
        ],
    )
    original_name = models.CharField(max_length=255)
    content_type = models.CharField(max_length=120, blank=True)
    size_bytes = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]

    def __str__(self) -> str:
        return self.original_name


class LifecycleEvent(models.Model):
    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name="lifecycle_events")
    actor = models.ForeignKey(User, on_delete=models.PROTECT, related_name="ticket_lifecycle_events")
    previous_status = models.CharField(max_length=40, choices=TicketStatus.choices)
    new_status = models.CharField(max_length=40, choices=TicketStatus.choices)
    note = models.TextField(blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["created_at"]

    def __str__(self) -> str:
        return f"{self.ticket_id}: {self.previous_status} -> {self.new_status}"


class NotificationPreference(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="notification_preference")
    email_on_status_change = models.BooleanField(default=True)
    email_on_thread_message = models.BooleanField(default=True)

    def __str__(self) -> str:
        return f"Notification preferences for {self.user}"
