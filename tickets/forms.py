from django import forms

from .models import (
    Attachment,
    DepartmentIntakeFieldType,
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
    intake_field_prefix = "department_intake_"

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
        self.department_intake_fields = self._department_intake_fields()
        self.selected_department = self._selected_department()
        for intake_field in self.department_intake_fields:
            form_field = self._build_department_intake_form_field(intake_field)
            if self.selected_department and intake_field.department_id == self.selected_department.pk:
                form_field.required = intake_field.is_required
            form_field.widget.attrs["data-department-intake-input"] = str(intake_field.department_id)
            self.fields[self._department_intake_field_name(intake_field)] = form_field

    def _affected_system_queryset(self, user):
        return System.visible_to(user).select_related("default_department").prefetch_related(
            "default_department__intake_fields"
        )

    def _department_intake_fields(self):
        department_ids = [
            system.default_department_id
            for system in self.fields["affected_system"].queryset
            if system.default_department_id
        ]
        fields_by_id = {}
        for system in self.fields["affected_system"].queryset:
            department = system.default_department
            if not department or department.pk not in department_ids:
                continue
            for intake_field in department.intake_fields.filter(is_active=True):
                fields_by_id[intake_field.pk] = intake_field
        return sorted(fields_by_id.values(), key=lambda field: (field.department.name, field.sort_order, field.label))

    def _selected_department(self):
        raw_system_id = None
        if self.is_bound:
            raw_system_id = self.data.get(self.add_prefix("affected_system"))
        elif self.initial.get("affected_system"):
            raw_system_id = self.initial["affected_system"]
        if not raw_system_id:
            return None
        try:
            system = self.fields["affected_system"].queryset.get(pk=raw_system_id)
        except (System.DoesNotExist, ValueError, TypeError):
            return None
        return system.default_department

    def _department_intake_field_name(self, intake_field):
        return f"{self.intake_field_prefix}{intake_field.pk}"

    def _build_department_intake_form_field(self, intake_field):
        kwargs = {
            "label": intake_field.label,
            "help_text": intake_field.help_text,
            "required": False,
        }
        if intake_field.field_type == DepartmentIntakeFieldType.TEXTAREA:
            return forms.CharField(widget=forms.Textarea(attrs={"rows": 3}), **kwargs)
        if intake_field.field_type == DepartmentIntakeFieldType.URL:
            return forms.URLField(**kwargs)
        if intake_field.field_type == DepartmentIntakeFieldType.SELECT:
            return forms.ChoiceField(choices=[("", "---------"), *intake_field.choice_pairs()], **kwargs)
        if intake_field.field_type == DepartmentIntakeFieldType.CHECKBOX:
            return forms.BooleanField(**kwargs)
        return forms.CharField(**kwargs)

    def department_intake_groups(self):
        groups = []
        fields_by_department = {}
        for intake_field in self.department_intake_fields:
            fields_by_department.setdefault(intake_field.department, []).append(intake_field)
        for department, intake_fields in fields_by_department.items():
            groups.append(
                {
                    "department": department,
                    "is_selected": self.selected_department and self.selected_department.pk == department.pk,
                    "bound_fields": [
                        self[self._department_intake_field_name(intake_field)] for intake_field in intake_fields
                    ],
                }
            )
        return groups

    @property
    def system_department_map(self):
        return {
            str(system.pk): str(system.default_department_id)
            for system in self.fields["affected_system"].queryset
            if system.default_department_id
        }

    def clean(self):
        cleaned_data = super().clean()
        selected_system = cleaned_data.get("affected_system")
        selected_department = selected_system.default_department if selected_system else None
        self.cleaned_intake_field_values = {}
        if not selected_department:
            return cleaned_data
        for intake_field in selected_department.intake_fields.filter(is_active=True):
            field_name = self._department_intake_field_name(intake_field)
            value = cleaned_data.get(field_name)
            if intake_field.is_required and (value in ("", None) or value is False):
                self.add_error(field_name, "This department requires this field.")
            if value in ("", None) or value is False:
                continue
            display_value = "Yes" if isinstance(value, bool) else value
            self.cleaned_intake_field_values[intake_field.slug] = {
                "label": intake_field.label,
                "value": value,
                "display_value": display_value,
                "field_type": intake_field.field_type,
            }
        return cleaned_data

    def save(self, commit=True):
        ticket = super().save(commit=False)
        ticket.intake_field_values = getattr(self, "cleaned_intake_field_values", {})
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
