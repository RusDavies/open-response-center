from django.contrib import admin

from .models import (
    Attachment,
    Department,
    DepartmentIntakeField,
    KnowledgeBaseArticle,
    LifecycleEvent,
    NotificationPreference,
    OperationsAgentToken,
    OperationalIncident,
    SlaPolicy,
    System,
    Ticket,
    TicketKnowledgeBaseLink,
    TicketMessage,
    TicketWorkflowChecklistItem,
    WorkflowChecklistItemTemplate,
    WorkflowTemplate,
)


class TicketMessageInline(admin.TabularInline):
    model = TicketMessage
    extra = 0
    readonly_fields = ["created_at"]


class AttachmentInline(admin.TabularInline):
    model = Attachment
    extra = 0
    readonly_fields = ["original_name", "content_type", "size_bytes", "created_at"]


class LifecycleEventInline(admin.TabularInline):
    model = LifecycleEvent
    extra = 0
    readonly_fields = ["actor", "previous_status", "new_status", "note", "created_at"]
    can_delete = False


class OperationalIncidentInline(admin.TabularInline):
    model = OperationalIncident
    extra = 0
    readonly_fields = [
        "backend",
        "reference",
        "status",
        "scope",
        "actionability",
        "access_level",
        "exposure",
        "risk",
        "p_level",
        "human_input_required",
        "path",
        "evidence_path",
        "created_by",
        "created_at",
        "updated_at",
    ]
    can_delete = False


class TicketKnowledgeBaseLinkInline(admin.TabularInline):
    model = TicketKnowledgeBaseLink
    extra = 0
    autocomplete_fields = ["article", "linked_by"]
    readonly_fields = ["created_at"]


class TicketWorkflowChecklistItemInline(admin.TabularInline):
    model = TicketWorkflowChecklistItem
    extra = 0
    readonly_fields = ["completed_by", "completed_at", "created_at"]


@admin.register(Ticket)
class TicketAdmin(admin.ModelAdmin):
    list_display = [
        "id",
        "title",
        "status",
        "impact",
        "sla_state",
        "affected_system",
        "department",
        "reporter",
        "operator",
    ]
    list_filter = ["status", "impact", "affected_system", "department", "workflow_template"]
    search_fields = [
        "title",
        "description",
        "issue_summary",
        "reproduction_steps",
        "expected_outcome",
        "actual_outcome",
        "additional_context",
        "incident_reference",
        "engineering_reference",
    ]
    autocomplete_fields = ["reporter", "operator", "affected_system", "department", "workflow_template"]
    readonly_fields = ["first_response_at", "resolved_at"]
    inlines = [
        TicketMessageInline,
        AttachmentInline,
        TicketWorkflowChecklistItemInline,
        TicketKnowledgeBaseLinkInline,
        OperationalIncidentInline,
        LifecycleEventInline,
    ]


class WorkflowChecklistItemTemplateInline(admin.TabularInline):
    model = WorkflowChecklistItemTemplate
    extra = 1


class DepartmentIntakeFieldInline(admin.TabularInline):
    model = DepartmentIntakeField
    extra = 1
    prepopulated_fields = {"slug": ["label"]}


@admin.register(Department)
class DepartmentAdmin(admin.ModelAdmin):
    list_display = ["name", "slug", "is_active"]
    filter_horizontal = ["operator_groups"]
    prepopulated_fields = {"slug": ["name"]}
    search_fields = ["name", "description"]
    inlines = [DepartmentIntakeFieldInline]


@admin.register(WorkflowTemplate)
class WorkflowTemplateAdmin(admin.ModelAdmin):
    list_display = ["name", "department", "default_impact", "incident_promotion_expected", "is_active"]
    list_filter = ["department", "default_impact", "incident_promotion_expected", "is_active"]
    search_fields = ["name", "summary"]
    autocomplete_fields = ["department"]
    inlines = [WorkflowChecklistItemTemplateInline]


@admin.register(KnowledgeBaseArticle)
class KnowledgeBaseArticleAdmin(admin.ModelAdmin):
    list_display = ["title", "audience", "is_published", "updated_at"]
    list_filter = ["audience", "is_published", "systems"]
    search_fields = ["title", "summary", "body", "tags"]
    prepopulated_fields = {"slug": ["title"]}
    filter_horizontal = ["systems"]
    autocomplete_fields = ["created_by", "updated_by"]
    readonly_fields = ["created_at", "updated_at"]


@admin.register(TicketKnowledgeBaseLink)
class TicketKnowledgeBaseLinkAdmin(admin.ModelAdmin):
    list_display = ["ticket", "article", "linked_by", "created_at"]
    search_fields = ["ticket__title", "article__title", "note"]
    autocomplete_fields = ["ticket", "article", "linked_by"]
    readonly_fields = ["created_at"]


@admin.register(SlaPolicy)
class SlaPolicyAdmin(admin.ModelAdmin):
    list_display = ["impact", "response_minutes", "resolution_minutes", "is_active", "updated_at"]
    list_filter = ["impact", "is_active"]
    readonly_fields = ["created_at", "updated_at"]


@admin.register(System)
class SystemAdmin(admin.ModelAdmin):
    list_display = ["name", "slug", "default_department", "default_workflow_template", "is_active"]
    list_filter = ["default_department", "default_workflow_template", "is_active"]
    filter_horizontal = ["visible_to_users", "visible_to_groups"]
    prepopulated_fields = {"slug": ["name"]}
    search_fields = ["name", "description"]
    autocomplete_fields = ["default_department", "default_workflow_template"]


@admin.register(TicketMessage)
class TicketMessageAdmin(admin.ModelAdmin):
    list_display = ["ticket", "author", "is_operator_note", "created_at"]
    list_filter = ["is_operator_note", "created_at"]
    search_fields = ["body", "ticket__title"]


@admin.register(Attachment)
class AttachmentAdmin(admin.ModelAdmin):
    list_display = ["ticket", "original_name", "uploaded_by", "size_bytes", "created_at"]
    search_fields = ["original_name", "ticket__title"]


@admin.register(LifecycleEvent)
class LifecycleEventAdmin(admin.ModelAdmin):
    list_display = ["ticket", "previous_status", "new_status", "actor", "created_at"]
    list_filter = ["new_status", "created_at"]
    search_fields = ["ticket__title", "note"]


@admin.register(NotificationPreference)
class NotificationPreferenceAdmin(admin.ModelAdmin):
    list_display = ["user", "email_on_status_change", "email_on_thread_message"]


@admin.register(OperationalIncident)
class OperationalIncidentAdmin(admin.ModelAdmin):
    list_display = ["reference", "backend", "ticket", "status", "p_level", "risk", "exposure", "created_by", "created_at"]
    list_filter = ["backend", "status", "p_level", "risk", "exposure", "created_at"]
    search_fields = ["reference", "title", "ticket__title", "path"]
    readonly_fields = ["created_at", "updated_at"]


@admin.register(OperationsAgentToken)
class OperationsAgentTokenAdmin(admin.ModelAdmin):
    list_display = ["name", "user", "prefix", "is_active", "last_used_at", "created_at"]
    list_filter = ["is_active", "created_at", "last_used_at"]
    search_fields = ["name", "user__username", "prefix"]
    readonly_fields = ["prefix", "token_hash", "last_used_at", "created_at"]
