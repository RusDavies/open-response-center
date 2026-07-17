from django import forms

from .models import (
    Attachment,
    IncidentAccessLevel,
    IncidentActionability,
    IncidentExposure,
    IncidentPLevel,
    IncidentRisk,
    IncidentScope,
    KnowledgeBaseArticle,
    NotificationPreference,
    HumanInputRequired,
    System,
    Ticket,
    TicketKnowledgeBaseLink,
    TicketMessage,
    TicketStatus,
)


class TicketCreateForm(forms.ModelForm):
    required_intake_fields = ["issue_summary", "reproduction_steps", "expected_outcome", "actual_outcome"]

    class Meta:
        model = Ticket
        fields = [
            "title",
            "affected_system",
            "impact",
            "issue_summary",
            "reproduction_steps",
            "expected_outcome",
            "actual_outcome",
            "additional_context",
        ]
        labels = {
            "title": "Short title",
            "issue_summary": "Summary of issue",
            "reproduction_steps": "Steps to reproduce",
            "expected_outcome": "Expected outcome",
            "actual_outcome": "Actual outcome",
            "additional_context": "Additional context",
        }
        help_texts = {
            "title": "A brief label for the ticket list.",
            "reproduction_steps": "List what you did before the problem happened.",
            "additional_context": "Optional logs, timing, related changes, or anything else that may matter.",
        }
        widgets = {
            "issue_summary": forms.Textarea(attrs={"rows": 3}),
            "reproduction_steps": forms.Textarea(
                attrs={"rows": 5, "placeholder": "1. Open ...\n2. Click ...\n3. See ..."}
            ),
            "expected_outcome": forms.Textarea(attrs={"rows": 3}),
            "actual_outcome": forms.Textarea(attrs={"rows": 3}),
            "additional_context": forms.Textarea(attrs={"rows": 3}),
        }

    def __init__(self, *args, **kwargs):
        user = kwargs.pop("user", None)
        super().__init__(*args, **kwargs)
        if user is not None:
            self.fields["affected_system"].queryset = self._affected_system_queryset(user)
        for field_name in self.required_intake_fields:
            self.fields[field_name].required = True

    def _affected_system_queryset(self, user):
        return System.visible_to(user)

    def save(self, commit=True):
        ticket = super().save(commit=False)
        ticket.description = ticket.build_description()
        if commit:
            ticket.save()
            self.save_m2m()
        return ticket


class AttachmentUploadForm(forms.ModelForm):
    file = forms.FileField(required=False)

    class Meta:
        model = Attachment
        fields = ["file"]


class NotificationPreferenceForm(forms.ModelForm):
    class Meta:
        model = NotificationPreference
        fields = ["email_on_status_change", "email_on_thread_message"]
        labels = {
            "email_on_status_change": "Email me when ticket status changes",
            "email_on_thread_message": "Email me when someone adds a ticket reply",
        }
        help_texts = {
            "email_on_status_change": "Status updates include lifecycle changes such as in progress, fixed, or closed.",
            "email_on_thread_message": "Internal operator notes never send reporter-facing email.",
        }


class MessageForm(forms.ModelForm):
    class Meta:
        model = TicketMessage
        fields = ["body"]
        widgets = {
            "body": forms.Textarea(attrs={"rows": 4, "placeholder": "Add a reply or update"}),
        }


class InternalNoteForm(forms.ModelForm):
    is_operator_note = forms.BooleanField(widget=forms.HiddenInput, initial=True, required=False)

    class Meta:
        model = TicketMessage
        fields = ["body", "is_operator_note"]
        labels = {
            "body": "Internal note",
        }
        widgets = {
            "body": forms.Textarea(attrs={"rows": 4, "placeholder": "Add an operator-only note"}),
        }


class OperatorUpdateForm(forms.ModelForm):
    note = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={"rows": 3, "placeholder": "Optional status-change note"}),
    )

    class Meta:
        model = Ticket
        fields = ["status", "operator", "department", "workflow_template", "incident_reference", "engineering_reference"]

    def clean_status(self):
        status = self.cleaned_data["status"]
        valid_statuses = {choice[0] for choice in TicketStatus.choices}
        if status not in valid_statuses:
            raise forms.ValidationError("Unsupported lifecycle status.")
        return status


class KnowledgeBaseArticleForm(forms.ModelForm):
    class Meta:
        model = KnowledgeBaseArticle
        fields = ["title", "slug", "summary", "body", "audience", "systems", "tags", "is_published"]
        labels = {
            "is_published": "Published",
        }
        help_texts = {
            "slug": "Leave blank to derive it from the title.",
            "tags": "Comma-separated internal tags such as email, gateway, uploads.",
        }
        widgets = {
            "summary": forms.Textarea(attrs={"rows": 3}),
            "body": forms.Textarea(attrs={"rows": 12}),
        }


class TicketKnowledgeBaseLinkForm(forms.ModelForm):
    class Meta:
        model = TicketKnowledgeBaseLink
        fields = ["article", "note"]
        widgets = {
            "note": forms.Textarea(attrs={"rows": 3, "placeholder": "Optional context for this link"}),
        }

    def __init__(self, *args, **kwargs):
        user = kwargs.pop("user", None)
        super().__init__(*args, **kwargs)
        queryset = KnowledgeBaseArticle.visible_to(user) if user is not None else KnowledgeBaseArticle.objects.none()
        self.fields["article"].queryset = queryset.order_by("title")


class IncidentClassificationForm(forms.Form):
    scope = forms.ChoiceField(choices=IncidentScope.choices, initial=IncidentScope.OWNED_SOFTWARE)
    actionability = forms.ChoiceField(
        choices=IncidentActionability.choices,
        initial=IncidentActionability.AUTO_FIX,
    )
    access_level = forms.ChoiceField(
        choices=IncidentAccessLevel.choices,
        initial=IncidentAccessLevel.LOCAL_SHELL,
    )
    exposure = forms.ChoiceField(
        choices=IncidentExposure.choices,
        initial=IncidentExposure.PRIVATE_CHANNEL,
    )
    risk = forms.ChoiceField(choices=IncidentRisk.choices, initial=IncidentRisk.MEDIUM)
    p_level = forms.ChoiceField(choices=IncidentPLevel.choices, initial=IncidentPLevel.P3, label="P-level")
    human_input_required = forms.ChoiceField(choices=HumanInputRequired.choices, initial=HumanInputRequired.NO)
    classification_note = forms.CharField(
        required=False,
        widget=forms.Textarea(
            attrs={
                "rows": 3,
                "placeholder": "Why this classification is appropriate",
            }
        ),
    )
