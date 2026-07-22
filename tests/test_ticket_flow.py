from datetime import timedelta
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core import mail
from django.core.management import call_command
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from tickets.models import (
    Attachment,
    Department,
    DepartmentIntakeField,
    DepartmentIntakeFieldType,
    ImpactLevel,
    KnowledgeBaseArticle,
    KnowledgeBaseAudience,
    LifecycleEvent,
    NotificationPreference,
    OperationsAgentScope,
    OperationsAgentToken,
    OperationalIncident,
    SlaPolicy,
    System,
    Ticket,
    TicketKnowledgeBaseLink,
    TicketStatus,
    TicketWorkflowChecklistItem,
    WorkflowChecklistItemTemplate,
    WorkflowTemplate,
)


class TicketFlowTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.reporter = User.objects.create_user("reporter", password="reporter")
        self.other_reporter = User.objects.create_user("other", password="other")
        self.operator = User.objects.create_user("operator", password="operator", is_staff=True)
        self.system = System.objects.create(name="OpenClaw Runtime", slug="openclaw-runtime")

    def incident_classification_data(self):
        return {
            "scope": "openclaw-local",
            "actionability": "auto-fix",
            "access_level": "local-shell",
            "exposure": "private-channel",
            "risk": "high",
            "p_level": "P2",
            "human_input_required": "decision",
            "classification_note": "Runtime failures need active operator triage.",
        }

    def issue_agent_token(self, *, user=None, scopes=None):
        user = user or self.operator
        scopes = scopes or [scope.value for scope in OperationsAgentScope]
        return OperationsAgentToken.issue(
            name=f"{user.username}-agent-{OperationsAgentToken.objects.count()}",
            user=user,
            scopes=scopes,
        )

    def api_headers(self, raw_token):
        return {
            "HTTP_AUTHORIZATION": f"Bearer {raw_token}",
            "content_type": "application/json",
        }

    def test_reporter_can_create_ticket(self):
        client = Client()
        client.force_login(self.reporter)

        response = client.post(
            reverse("ticket-create"),
            {
                "title": "Node upload failure",
                "affected_system": self.system.pk,
                "impact": "high",
                "issue_summary": "Upload fails after the first screenshot.",
                "reproduction_steps": "1. Open the node.\n2. Upload screenshots.",
                "expected_outcome": "All screenshots upload.",
                "actual_outcome": "The first screenshot uploads, then the node disconnects.",
                "additional_context": "Seen twice today.",
            },
        )

        ticket = Ticket.objects.get()
        self.assertRedirects(response, reverse("ticket-detail", kwargs={"pk": ticket.pk}))
        self.assertEqual(ticket.reporter, self.reporter)
        self.assertEqual(ticket.status, TicketStatus.RECEIVED)
        self.assertEqual(ticket.issue_summary, "Upload fails after the first screenshot.")
        self.assertIn("Steps to reproduce", ticket.description)
        self.assertIn("Expected outcome", ticket.description)
        self.assertIn("Actual outcome", ticket.description)
        self.assertEqual(ticket.messages.count(), 1)
        self.assertEqual(ticket.messages.get().body, ticket.description)

    def test_ticket_uses_system_department_workflow_defaults(self):
        department = Department.objects.create(name="Security", slug="security")
        workflow = WorkflowTemplate.objects.create(
            department=department,
            name="Security triage",
            default_impact=ImpactLevel.HIGH,
            incident_promotion_expected=True,
        )
        WorkflowChecklistItemTemplate.objects.create(
            workflow_template=workflow,
            title="Classify exposure",
            description="Confirm data exposure, access level, and risk.",
            sort_order=10,
        )
        WorkflowChecklistItemTemplate.objects.create(
            workflow_template=workflow,
            title="Verify remediation",
            blocks_closure=True,
            sort_order=20,
        )
        self.system.default_department = department
        self.system.default_workflow_template = workflow
        self.system.save(update_fields=["default_department", "default_workflow_template"])

        client = Client()
        client.force_login(self.reporter)

        response = client.post(
            reverse("ticket-create"),
            {
                "title": "Token leaked in log",
                "affected_system": self.system.pk,
                "impact": "medium",
                "issue_summary": "A bearer token appears in a runtime log.",
                "reproduction_steps": "1. Trigger a failing request.\n2. Open the log.",
                "expected_outcome": "Logs redact secrets.",
                "actual_outcome": "The token is visible.",
                "additional_context": "",
            },
        )

        ticket = Ticket.objects.get(title="Token leaked in log")
        self.assertRedirects(response, reverse("ticket-detail", kwargs={"pk": ticket.pk}))
        self.assertEqual(ticket.department, department)
        self.assertEqual(ticket.workflow_template, workflow)
        self.assertEqual(ticket.impact, ImpactLevel.HIGH)
        self.assertEqual(
            list(ticket.workflow_items.order_by("sort_order").values_list("title", flat=True)),
            ["Classify exposure", "Verify remediation"],
        )

    def test_department_intake_fields_render_and_persist_with_ticket(self):
        department = Department.objects.create(name="Security", slug="security")
        asset_field = DepartmentIntakeField.objects.create(
            department=department,
            label="Affected asset",
            slug="affected-asset",
            help_text="Hostname, device, or account involved.",
            is_required=True,
            sort_order=10,
        )
        severity_field = DepartmentIntakeField.objects.create(
            department=department,
            label="Suspected exposure",
            slug="suspected-exposure",
            field_type=DepartmentIntakeFieldType.SELECT,
            choices="No data exposed\nInternal data\nCustomer data",
            sort_order=20,
        )
        self.system.default_department = department
        self.system.save(update_fields=["default_department"])

        client = Client()
        client.force_login(self.reporter)
        response = client.get(reverse("ticket-create"))

        self.assertContains(response, "Department intake")
        self.assertContains(response, "Affected asset")
        self.assertContains(response, "Suspected exposure")
        self.assertContains(response, "Hostname, device, or account involved.")

        response = client.post(
            reverse("ticket-create"),
            {
                "title": "Token leaked in log",
                "affected_system": self.system.pk,
                "impact": "medium",
                "issue_summary": "A bearer token appears in a runtime log.",
                "reproduction_steps": "1. Trigger a failing request.\n2. Open the log.",
                "expected_outcome": "Logs redact secrets.",
                "actual_outcome": "The token is visible.",
                "additional_context": "",
                f"department_intake_{asset_field.pk}": "node-17",
                f"department_intake_{severity_field.pk}": "Internal data",
            },
        )

        ticket = Ticket.objects.get(title="Token leaked in log")
        self.assertRedirects(response, reverse("ticket-detail", kwargs={"pk": ticket.pk}))
        self.assertEqual(ticket.intake_field_values["affected-asset"]["value"], "node-17")
        self.assertEqual(ticket.intake_field_values["suspected-exposure"]["value"], "Internal data")
        self.assertIn("Affected asset", ticket.description)
        self.assertIn("node-17", ticket.description)

        detail = client.get(reverse("ticket-detail", kwargs={"pk": ticket.pk}))
        self.assertContains(detail, "Department intake")
        self.assertContains(detail, "Affected asset")
        self.assertContains(detail, "node-17")

    def test_department_intake_required_fields_are_enforced(self):
        department = Department.objects.create(name="Hardware", slug="hardware")
        DepartmentIntakeField.objects.create(
            department=department,
            label="Device serial",
            slug="device-serial",
            is_required=True,
        )
        self.system.default_department = department
        self.system.save(update_fields=["default_department"])
        client = Client()
        client.force_login(self.reporter)

        response = client.post(
            reverse("ticket-create"),
            {
                "title": "Printer smoking",
                "affected_system": self.system.pk,
                "impact": "high",
                "issue_summary": "Printer smells hot.",
                "reproduction_steps": "1. Print a test page.",
                "expected_outcome": "Paper comes out.",
                "actual_outcome": "Smoke comes out.",
                "additional_context": "",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "This department requires this field.")
        self.assertFalse(Ticket.objects.filter(title="Printer smoking").exists())

    def test_blocking_workflow_items_must_be_done_before_closing_ticket(self):
        department = Department.objects.create(name="Software", slug="software")
        workflow = WorkflowTemplate.objects.create(department=department, name="Bug triage")
        WorkflowChecklistItemTemplate.objects.create(
            workflow_template=workflow,
            title="Confirm fix verification",
            blocks_closure=True,
        )
        ticket = Ticket.objects.create(
            title="Widget fails",
            reporter=self.reporter,
            affected_system=self.system,
            department=department,
            workflow_template=workflow,
            issue_summary="Widget fails.",
            reproduction_steps="Open widget.",
            expected_outcome="Widget works.",
            actual_outcome="Widget fails.",
        )
        ticket.generate_workflow_checklist()
        checklist_item = ticket.workflow_items.get()
        client = Client()
        client.force_login(self.operator)

        response = client.post(
            reverse("operator-update", kwargs={"pk": ticket.pk}),
            {
                "status": TicketStatus.CLOSED,
                "operator": self.operator.pk,
                "department": department.pk,
                "workflow_template": workflow.pk,
                "incident_reference": "",
                "engineering_reference": "",
                "note": "Trying to close before verification.",
            },
        )

        ticket.refresh_from_db()
        self.assertRedirects(response, reverse("ticket-detail", kwargs={"pk": ticket.pk}))
        self.assertEqual(ticket.status, TicketStatus.RECEIVED)

        response = client.post(
            reverse("ticket-update-workflow", kwargs={"pk": ticket.pk}),
            {"done_items": [str(checklist_item.pk)]},
        )
        checklist_item.refresh_from_db()
        self.assertRedirects(response, reverse("ticket-detail", kwargs={"pk": ticket.pk}))
        self.assertTrue(checklist_item.is_done)
        self.assertEqual(checklist_item.completed_by, self.operator)

        response = client.post(
            reverse("operator-update", kwargs={"pk": ticket.pk}),
            {
                "status": TicketStatus.CLOSED,
                "operator": self.operator.pk,
                "department": department.pk,
                "workflow_template": workflow.pk,
                "incident_reference": "",
                "engineering_reference": "",
                "note": "Verified.",
            },
        )

        ticket.refresh_from_db()
        self.assertRedirects(response, reverse("ticket-detail", kwargs={"pk": ticket.pk}))
        self.assertEqual(ticket.status, TicketStatus.CLOSED)

    def test_operator_assigning_workflow_generates_checklist_items(self):
        department = Department.objects.create(name="Operations", slug="operations")
        workflow = WorkflowTemplate.objects.create(department=department, name="Ops triage")
        WorkflowChecklistItemTemplate.objects.create(workflow_template=workflow, title="Check monitoring")
        ticket = Ticket.objects.create(
            title="Queue lag",
            reporter=self.reporter,
            affected_system=self.system,
            issue_summary="Queue is lagging.",
            reproduction_steps="Open dashboard.",
            expected_outcome="Queue drains.",
            actual_outcome="Queue grows.",
        )
        client = Client()
        client.force_login(self.operator)

        response = client.post(
            reverse("operator-update", kwargs={"pk": ticket.pk}),
            {
                "status": TicketStatus.RECEIVED,
                "operator": self.operator.pk,
                "department": department.pk,
                "workflow_template": workflow.pk,
                "incident_reference": "",
                "engineering_reference": "",
                "note": "",
            },
        )

        ticket.refresh_from_db()
        self.assertRedirects(response, reverse("ticket-detail", kwargs={"pk": ticket.pk}))
        self.assertEqual(ticket.department, department)
        self.assertEqual(ticket.workflow_template, workflow)
        self.assertTrue(TicketWorkflowChecklistItem.objects.filter(ticket=ticket, title="Check monitoring").exists())

    def test_reporter_only_sees_allowed_systems_on_new_ticket_form(self):
        private_system = System.objects.create(name="Private Lab", slug="private-lab")
        private_system.visible_to_users.add(self.other_reporter)
        inactive_system = System.objects.create(name="Retired System", slug="retired-system", is_active=False)

        client = Client()
        client.force_login(self.reporter)

        response = client.get(reverse("ticket-create"))

        self.assertEqual(response.status_code, 200)
        system_queryset = response.context["form"].fields["affected_system"].queryset
        self.assertIn(self.system, system_queryset)
        self.assertNotIn(private_system, system_queryset)
        self.assertNotIn(inactive_system, system_queryset)

    def test_reporter_can_see_system_allowed_by_group(self):
        group = Group.objects.create(name="Lab reporters")
        self.reporter.groups.add(group)
        lab_system = System.objects.create(name="Group Lab", slug="group-lab")
        lab_system.visible_to_groups.add(group)

        client = Client()
        client.force_login(self.reporter)

        response = client.get(reverse("ticket-create"))

        self.assertEqual(response.status_code, 200)
        self.assertIn(lab_system, response.context["form"].fields["affected_system"].queryset)

    def test_reporter_cannot_submit_ticket_for_hidden_system_by_tampering(self):
        private_system = System.objects.create(name="Private Lab", slug="private-lab")
        private_system.visible_to_users.add(self.other_reporter)
        client = Client()
        client.force_login(self.reporter)

        response = client.post(
            reverse("ticket-create"),
            {
                "title": "Hidden system report",
                "affected_system": private_system.pk,
                "impact": "medium",
                "issue_summary": "This should not bind to an unauthorized system.",
                "reproduction_steps": "1. Tamper with the form.",
                "expected_outcome": "The form rejects the system.",
                "actual_outcome": "The hidden system was submitted.",
                "additional_context": "",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertFormError(
            response.context["form"],
            "affected_system",
            "Select a valid choice. That choice is not one of the available choices.",
        )
        self.assertFalse(Ticket.objects.filter(title="Hidden system report").exists())

    def test_operator_sees_all_active_systems_on_new_ticket_form(self):
        private_system = System.objects.create(name="Private Lab", slug="private-lab")
        private_system.visible_to_users.add(self.other_reporter)
        inactive_system = System.objects.create(name="Retired System", slug="retired-system", is_active=False)
        client = Client()
        client.force_login(self.operator)

        response = client.get(reverse("ticket-create"))

        system_queryset = response.context["form"].fields["affected_system"].queryset
        self.assertIn(self.system, system_queryset)
        self.assertIn(private_system, system_queryset)
        self.assertNotIn(inactive_system, system_queryset)

    def test_new_ticket_form_renders_structured_fields(self):
        client = Client()
        client.force_login(self.reporter)

        response = client.get(reverse("ticket-create"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Summary of issue")
        self.assertContains(response, "Steps to reproduce")
        self.assertContains(response, "Expected outcome")
        self.assertContains(response, "Actual outcome")
        self.assertContains(response, "Before uploading logs or screenshots")
        self.assertContains(response, "Remove passwords, tokens, API keys, session cookies, and recovery codes.")
        self.assertContains(response, "Keep timestamps, error text, request IDs, and file names")

    def test_login_page_renders_branding(self):
        response = Client().get(reverse("login"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Open Response Center")
        self.assertContains(response, "ORC")
        self.assertNotContains(response, "redshieldknight-header.svg")
        self.assertNotContains(response, "redshieldknight-shield.svg")

    def test_remote_user_header_is_ignored_by_default(self):
        User = get_user_model()

        response = Client().get(reverse("ticket-list"), HTTP_X_REMOTE_USER="internal-reporter")

        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response["Location"])
        self.assertFalse(User.objects.filter(username="internal-reporter").exists())

    def test_remote_user_header_authenticates_when_enabled(self):
        User = get_user_model()
        client = Client()

        with override_settings(ORC_ENABLE_REMOTE_USER_AUTH=True):
            response = client.get(
                reverse("ticket-list"),
                HTTP_X_REMOTE_USER="internal-reporter",
                HTTP_X_REMOTE_EMAIL="internal-reporter@example.test",
                HTTP_X_REMOTE_FIRST_NAME="Internal",
                HTTP_X_REMOTE_LAST_NAME="Reporter",
            )

        user = User.objects.get(username="internal-reporter")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(user.email, "internal-reporter@example.test")
        self.assertEqual(user.first_name, "Internal")
        self.assertEqual(user.last_name, "Reporter")
        self.assertFalse(user.has_usable_password())

    def test_user_can_update_email_preferences(self):
        client = Client()
        client.force_login(self.reporter)

        response = client.get(reverse("notification-preferences"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Email me when ticket status changes")
        self.assertContains(response, "Email me when someone adds a ticket reply")

        response = client.post(
            reverse("notification-preferences"),
            {
                "email_on_status_change": "on",
            },
        )

        preference = NotificationPreference.objects.get(user=self.reporter)
        self.assertRedirects(response, reverse("notification-preferences"))
        self.assertTrue(preference.email_on_status_change)
        self.assertFalse(preference.email_on_thread_message)

    def test_ticket_detail_renders_structured_intake(self):
        ticket = Ticket.objects.create(
            title="Structured report",
            reporter=self.reporter,
            issue_summary="Dashboard count is wrong.",
            reproduction_steps="1. Open dashboard.\n2. Count tickets.",
            expected_outcome="The count matches the ticket table.",
            actual_outcome="The count is one too high.",
            additional_context="Started after the demo seed ran.",
        )
        client = Client()
        client.force_login(self.reporter)

        response = client.get(reverse("ticket-detail", kwargs={"pk": ticket.pk}))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Summary of issue")
        self.assertContains(response, "Steps to reproduce")
        self.assertContains(response, "Expected outcome")
        self.assertContains(response, "Actual outcome")
        self.assertContains(response, "Dashboard count is wrong.")
        self.assertContains(response, "Redact before uploading")
        self.assertContains(response, "Blur private messages, email addresses, phone numbers")

    def test_reporter_cannot_view_other_reporters_ticket(self):
        ticket = Ticket.objects.create(
            title="Private ticket",
            description="Reporter-only details",
            reporter=self.reporter,
        )
        client = Client()
        client.force_login(self.other_reporter)

        response = client.get(reverse("ticket-detail", kwargs={"pk": ticket.pk}))

        self.assertEqual(response.status_code, 404)

    def test_internal_knowledge_base_visibility_respects_audience(self):
        public_article = KnowledgeBaseArticle.objects.create(
            title="Gateway upload retries",
            slug="gateway-upload-retries",
            summary="What to check when uploads retry.",
            body="Check gateway logs and retry queue.",
            audience=KnowledgeBaseAudience.ALL_INTERNAL,
            is_published=True,
            created_by=self.operator,
            updated_by=self.operator,
        )
        public_article.systems.add(self.system)
        operator_article = KnowledgeBaseArticle.objects.create(
            title="Private operator runbook",
            slug="private-operator-runbook",
            summary="Operator-only steps.",
            body="Use operator-only tooling.",
            audience=KnowledgeBaseAudience.OPERATORS,
            is_published=True,
            created_by=self.operator,
            updated_by=self.operator,
        )
        draft_article = KnowledgeBaseArticle.objects.create(
            title="Draft article",
            slug="draft-article",
            summary="Not published.",
            body="Draft.",
            audience=KnowledgeBaseAudience.ALL_INTERNAL,
            is_published=False,
            created_by=self.operator,
            updated_by=self.operator,
        )
        client = Client()
        client.force_login(self.reporter)

        response = client.get(reverse("knowledge-base-list"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, public_article.title)
        self.assertNotContains(response, operator_article.title)
        self.assertNotContains(response, draft_article.title)

        hidden = client.get(reverse("knowledge-base-detail", kwargs={"slug": operator_article.slug}))
        self.assertEqual(hidden.status_code, 404)

    def test_operator_can_create_and_link_knowledge_article_to_ticket(self):
        ticket = Ticket.objects.create(
            title="Repeated upload failure",
            description="Upload keeps failing.",
            reporter=self.reporter,
            affected_system=self.system,
        )
        article = KnowledgeBaseArticle.objects.create(
            title="Upload failure runbook",
            slug="upload-failure-runbook",
            summary="Reusable upload triage.",
            body="Check logs.",
            audience=KnowledgeBaseAudience.ALL_INTERNAL,
            is_published=True,
            created_by=self.operator,
            updated_by=self.operator,
        )
        client = Client()
        client.force_login(self.operator)

        response = client.post(
            reverse("ticket-link-knowledge-base", kwargs={"pk": ticket.pk}),
            {"article": article.pk, "note": "Use this when uploads fail."},
        )

        self.assertRedirects(response, reverse("ticket-detail", kwargs={"pk": ticket.pk}))
        link = TicketKnowledgeBaseLink.objects.get(ticket=ticket, article=article)
        self.assertEqual(link.note, "Use this when uploads fail.")

        detail = client.get(reverse("ticket-detail", kwargs={"pk": ticket.pk}))
        self.assertContains(detail, "Upload failure runbook")

    def test_operator_can_draft_knowledge_article_from_ticket(self):
        ticket = Ticket.objects.create(
            title="Node disconnects during upload",
            reporter=self.reporter,
            affected_system=self.system,
            issue_summary="The node disconnects when uploading several files.",
            reproduction_steps="1. Upload files.\n2. Watch disconnect.",
            expected_outcome="The upload completes.",
            actual_outcome="The node disconnects.",
        )
        client = Client()
        client.force_login(self.operator)

        response = client.post(reverse("ticket-draft-knowledge-base", kwargs={"pk": ticket.pk}))

        article = KnowledgeBaseArticle.objects.get(slug__startswith=f"ticket-{ticket.pk}-")
        self.assertRedirects(response, article.get_absolute_url())
        self.assertEqual(article.audience, KnowledgeBaseAudience.OPERATORS)
        self.assertFalse(article.is_published)
        self.assertIn("Operator Notes", article.body)
        self.assertTrue(article.systems.filter(pk=self.system.pk).exists())
        self.assertTrue(TicketKnowledgeBaseLink.objects.filter(ticket=ticket, article=article).exists())

    def test_operator_status_update_records_lifecycle_event(self):
        ticket = Ticket.objects.create(
            title="Needs triage",
            description="Something is broken.",
            reporter=self.reporter,
        )
        client = Client()
        client.force_login(self.operator)

        response = client.post(
            reverse("operator-update", kwargs={"pk": ticket.pk}),
            {
                "status": TicketStatus.IN_PROGRESS,
                "operator": self.operator.pk,
                "incident_reference": "INC-2026-0001",
                "engineering_reference": "",
                "note": "Started investigation.",
            },
        )

        ticket.refresh_from_db()
        event = LifecycleEvent.objects.get()
        self.assertRedirects(response, reverse("ticket-detail", kwargs={"pk": ticket.pk}))
        self.assertEqual(ticket.status, TicketStatus.IN_PROGRESS)
        self.assertEqual(ticket.operator, self.operator)
        self.assertEqual(event.previous_status, TicketStatus.RECEIVED)
        self.assertEqual(event.new_status, TicketStatus.IN_PROGRESS)

    def test_operator_board_groups_tickets_by_lifecycle_status(self):
        triage_ticket = Ticket.objects.create(
            title="Needs triage",
            description="Something is broken.",
            reporter=self.reporter,
            affected_system=self.system,
            impact=ImpactLevel.HIGH,
        )
        progress_ticket = Ticket.objects.create(
            title="Fix in progress",
            description="Something else is broken.",
            reporter=self.other_reporter,
            affected_system=self.system,
            status=TicketStatus.IN_PROGRESS,
            operator=self.operator,
        )
        client = Client()
        client.force_login(self.operator)

        response = client.get(reverse("ticket-board"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Operator board")
        self.assertContains(response, "Received")
        self.assertContains(response, "In progress")
        self.assertContains(response, f"#{triage_ticket.pk} Needs triage")
        self.assertContains(response, f"#{progress_ticket.pk} Fix in progress")
        columns = response.context["board_columns"]
        received_column = next(column for column in columns if column["status"] == TicketStatus.RECEIVED)
        progress_column = next(column for column in columns if column["status"] == TicketStatus.IN_PROGRESS)
        self.assertEqual(list(received_column["tickets"]), [triage_ticket])
        self.assertEqual(list(progress_column["tickets"]), [progress_ticket])

    def test_operator_board_defaults_to_responsible_department_queue(self):
        security_group = Group.objects.create(name="security-operators")
        self.operator.groups.add(security_group)
        security = Department.objects.create(name="Security", slug="security")
        security.operator_groups.add(security_group)
        hardware_group = Group.objects.create(name="hardware-operators")
        hardware = Department.objects.create(name="Hardware", slug="hardware")
        hardware.operator_groups.add(hardware_group)
        open_queue = Department.objects.create(name="General", slug="general")
        owned_ticket = Ticket.objects.create(
            title="Security queue ticket",
            description="Security owns this.",
            reporter=self.reporter,
            affected_system=self.system,
            department=security,
        )
        hidden_ticket = Ticket.objects.create(
            title="Hardware queue ticket",
            description="Hardware owns this.",
            reporter=self.reporter,
            affected_system=self.system,
            department=hardware,
        )
        open_ticket = Ticket.objects.create(
            title="General queue ticket",
            description="No operator group owns this.",
            reporter=self.reporter,
            affected_system=self.system,
            department=open_queue,
        )
        assigned_ticket = Ticket.objects.create(
            title="Assigned hardware ticket",
            description="Assigned tickets stay in the operator queue.",
            reporter=self.reporter,
            affected_system=self.system,
            department=hardware,
            operator=self.operator,
        )
        unassigned_ticket = Ticket.objects.create(
            title="Unassigned department ticket",
            description="No department yet.",
            reporter=self.reporter,
            affected_system=self.system,
        )
        client = Client()
        client.force_login(self.operator)

        response = client.get(reverse("ticket-board"))

        self.assertContains(response, f"#{owned_ticket.pk} Security queue ticket")
        self.assertContains(response, f"#{open_ticket.pk} General queue ticket")
        self.assertContains(response, f"#{assigned_ticket.pk} Assigned hardware ticket")
        self.assertContains(response, f"#{unassigned_ticket.pk} Unassigned department ticket")
        self.assertNotContains(response, f"#{hidden_ticket.pk} Hardware queue ticket")
        department_slugs = {department.slug for department in response.context["departments"]}
        self.assertEqual(department_slugs, {"general", "hardware", "security"})

    def test_operator_ticket_list_can_filter_by_department(self):
        security_group = Group.objects.create(name="security-operators")
        self.operator.groups.add(security_group)
        security = Department.objects.create(name="Security", slug="security")
        security.operator_groups.add(security_group)
        general = Department.objects.create(name="General", slug="general")
        security_ticket = Ticket.objects.create(
            title="Security queue ticket",
            description="Security owns this.",
            reporter=self.reporter,
            affected_system=self.system,
            department=security,
        )
        Ticket.objects.create(
            title="General queue ticket",
            description="No operator group owns this.",
            reporter=self.reporter,
            affected_system=self.system,
            department=general,
        )
        client = Client()
        client.force_login(self.operator)

        response = client.get(reverse("ticket-list"), {"department": "security"})

        self.assertContains(response, "Security queue ticket")
        self.assertNotContains(response, "General queue ticket")
        self.assertEqual(list(response.context["tickets"]), [security_ticket])

    def test_admin_board_can_see_all_department_queues(self):
        admin = get_user_model().objects.create_superuser("admin", password="admin")
        security_group = Group.objects.create(name="security-operators")
        security = Department.objects.create(name="Security", slug="security")
        security.operator_groups.add(security_group)
        hidden_ticket = Ticket.objects.create(
            title="Security queue ticket",
            description="Security owns this.",
            reporter=self.reporter,
            affected_system=self.system,
            department=security,
        )
        client = Client()
        client.force_login(admin)

        response = client.get(reverse("ticket-board"))

        self.assertContains(response, f"#{hidden_ticket.pk} Security queue ticket")

    def test_reporter_cannot_view_operator_board(self):
        client = Client()
        client.force_login(self.reporter)

        response = client.get(reverse("ticket-board"))

        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response["Location"])

    def test_operator_status_update_starts_sla_response_clock(self):
        ticket = Ticket.objects.create(
            title="Needs response tracking",
            description="Something is broken.",
            reporter=self.reporter,
        )
        client = Client()
        client.force_login(self.operator)

        response = client.post(
            reverse("operator-update", kwargs={"pk": ticket.pk}),
            {
                "status": TicketStatus.TRIAGED,
                "operator": self.operator.pk,
                "incident_reference": "",
                "engineering_reference": "",
                "note": "Acknowledged.",
            },
        )

        ticket.refresh_from_db()
        self.assertRedirects(response, reverse("ticket-detail", kwargs={"pk": ticket.pk}))
        self.assertIsNotNone(ticket.first_response_at)
        self.assertEqual(ticket.sla_summary["response_state"], "met")

    def test_public_operator_reply_counts_as_first_response(self):
        ticket = Ticket.objects.create(
            title="Needs reply response tracking",
            description="Something is broken.",
            reporter=self.reporter,
        )
        client = Client()
        client.force_login(self.operator)

        response = client.post(
            reverse("ticket-add-message", kwargs={"pk": ticket.pk}),
            {"body": "We are looking at this now."},
        )

        ticket.refresh_from_db()
        self.assertRedirects(response, reverse("ticket-detail", kwargs={"pk": ticket.pk}))
        self.assertIsNotNone(ticket.first_response_at)

    def test_resolution_timestamp_is_set_and_cleared_on_reopen(self):
        ticket = Ticket.objects.create(
            title="Needs resolution tracking",
            description="Something is broken.",
            reporter=self.reporter,
        )

        ticket.transition_to(status=TicketStatus.FIXED, actor=self.operator, note="Fixed.")
        ticket.refresh_from_db()
        self.assertIsNotNone(ticket.resolved_at)

        ticket.transition_to(status=TicketStatus.IN_PROGRESS, actor=self.operator, note="Reopened.")
        ticket.refresh_from_db()
        self.assertIsNone(ticket.resolved_at)

    def test_sla_policy_overrides_default_windows(self):
        SlaPolicy.objects.create(impact=ImpactLevel.HIGH, response_minutes=30, resolution_minutes=90)
        ticket = Ticket.objects.create(
            title="Custom high impact SLA",
            description="Something is broken.",
            reporter=self.reporter,
            impact=ImpactLevel.HIGH,
        )

        self.assertEqual(ticket.sla_summary["response_minutes"], 30)
        self.assertEqual(ticket.sla_response_due_at, ticket.created_at + timedelta(minutes=30))
        self.assertEqual(ticket.sla_resolution_due_at, ticket.created_at + timedelta(minutes=90))

    def test_sla_report_command_reports_breached_open_tickets(self):
        ticket = Ticket.objects.create(
            title="Old critical ticket",
            description="Something is broken.",
            reporter=self.reporter,
            impact=ImpactLevel.CRITICAL,
        )
        Ticket.objects.filter(pk=ticket.pk).update(created_at=timezone.now() - timedelta(hours=2))
        output = StringIO()

        call_command("sla_report", "--breached-only", stdout=output)

        text = output.getvalue()
        self.assertIn(f"#{ticket.pk} breached Critical Received", text)
        self.assertIn("1 ticket(s) shown; 1 breached open SLA(s).", text)

    def test_attachment_download_is_authorized(self):
        ticket = Ticket.objects.create(
            title="Evidence",
            description="Has evidence.",
            reporter=self.reporter,
        )
        attachment = Attachment.objects.create(
            ticket=ticket,
            uploaded_by=self.reporter,
            file=SimpleUploadedFile("evidence.txt", b"hello", content_type="text/plain"),
            original_name="evidence.txt",
            content_type="text/plain",
            size_bytes=5,
        )

        client = Client()
        client.force_login(self.other_reporter)
        forbidden = client.get(reverse("attachment-download", kwargs={"pk": attachment.pk}))
        self.assertEqual(forbidden.status_code, 403)

        client.force_login(self.reporter)
        allowed = client.get(reverse("attachment-download", kwargs={"pk": attachment.pk}))
        self.assertEqual(allowed.status_code, 200)

    def test_attachment_cleanup_is_dry_run_by_default(self):
        with TemporaryDirectory() as media:
            with override_settings(MEDIA_ROOT=Path(media)):
                ticket = Ticket.objects.create(
                    title="Closed evidence",
                    description="Can age out.",
                    reporter=self.reporter,
                    status=TicketStatus.CLOSED,
                )
                attachment = Attachment.objects.create(
                    ticket=ticket,
                    uploaded_by=self.reporter,
                    file=SimpleUploadedFile("old.log", b"old", content_type="text/plain"),
                    original_name="old.log",
                    content_type="text/plain",
                    size_bytes=3,
                )
                Ticket.objects.filter(pk=ticket.pk).update(updated_at=timezone.now() - timedelta(days=120))
                output = StringIO()

                call_command("cleanup_attachments", stdout=output)

                attachment.refresh_from_db()
                self.assertTrue(attachment.file.storage.exists(attachment.file.name))
                self.assertIn("1 attachment(s) matched", output.getvalue())
                self.assertIn("Dry run only", output.getvalue())

    def test_attachment_cleanup_deletes_only_old_closed_ticket_attachments(self):
        with TemporaryDirectory() as media:
            with override_settings(MEDIA_ROOT=Path(media)):
                old_closed = Ticket.objects.create(
                    title="Old closed",
                    description="Delete evidence.",
                    reporter=self.reporter,
                    status=TicketStatus.CLOSED,
                )
                fresh_closed = Ticket.objects.create(
                    title="Fresh closed",
                    description="Keep evidence.",
                    reporter=self.reporter,
                    status=TicketStatus.CLOSED,
                )
                old_open = Ticket.objects.create(
                    title="Old open",
                    description="Keep evidence.",
                    reporter=self.reporter,
                    status=TicketStatus.IN_PROGRESS,
                )
                old_attachment = Attachment.objects.create(
                    ticket=old_closed,
                    uploaded_by=self.reporter,
                    file=SimpleUploadedFile("old.log", b"old", content_type="text/plain"),
                    original_name="old.log",
                    content_type="text/plain",
                    size_bytes=3,
                )
                fresh_attachment = Attachment.objects.create(
                    ticket=fresh_closed,
                    uploaded_by=self.reporter,
                    file=SimpleUploadedFile("fresh.log", b"fresh", content_type="text/plain"),
                    original_name="fresh.log",
                    content_type="text/plain",
                    size_bytes=5,
                )
                open_attachment = Attachment.objects.create(
                    ticket=old_open,
                    uploaded_by=self.reporter,
                    file=SimpleUploadedFile("open.log", b"open", content_type="text/plain"),
                    original_name="open.log",
                    content_type="text/plain",
                    size_bytes=4,
                )
                cutoff_time = timezone.now() - timedelta(days=120)
                Ticket.objects.filter(pk__in=[old_closed.pk, old_open.pk]).update(updated_at=cutoff_time)
                old_file_name = old_attachment.file.name
                fresh_file_name = fresh_attachment.file.name
                open_file_name = open_attachment.file.name
                output = StringIO()

                call_command("cleanup_attachments", "--delete", stdout=output)

                self.assertFalse(Attachment.objects.filter(pk=old_attachment.pk).exists())
                self.assertFalse(old_attachment.file.storage.exists(old_file_name))
                self.assertTrue(Attachment.objects.filter(pk=fresh_attachment.pk).exists())
                self.assertTrue(fresh_attachment.file.storage.exists(fresh_file_name))
                self.assertTrue(Attachment.objects.filter(pk=open_attachment.pk).exists())
                self.assertTrue(open_attachment.file.storage.exists(open_file_name))
                self.assertIn("1 attachment(s) deleted", output.getvalue())

    def test_operator_internal_note_is_hidden_from_reporter(self):
        self.reporter.email = "reporter@example.test"
        self.reporter.save(update_fields=["email"])
        ticket = Ticket.objects.create(
            title="Private triage",
            description="Reporter-visible details.",
            reporter=self.reporter,
        )
        operator_client = Client()
        operator_client.force_login(self.operator)

        response = operator_client.post(
            reverse("ticket-add-message", kwargs={"pk": ticket.pk}),
            {
                "body": "Check private remediation notes before replying.",
                "is_operator_note": "1",
            },
        )

        message = ticket.messages.get()
        self.assertRedirects(response, reverse("ticket-detail", kwargs={"pk": ticket.pk}))
        self.assertTrue(message.is_operator_note)
        self.assertEqual(len(mail.outbox), 0)

        operator_detail = operator_client.get(reverse("ticket-detail", kwargs={"pk": ticket.pk}))
        self.assertContains(operator_detail, "Check private remediation notes before replying.")
        self.assertContains(operator_detail, "Internal note")

        reporter_client = Client()
        reporter_client.force_login(self.reporter)
        reporter_detail = reporter_client.get(reverse("ticket-detail", kwargs={"pk": ticket.pk}))
        self.assertNotContains(reporter_detail, "Check private remediation notes before replying.")
        self.assertNotContains(reporter_detail, "Internal note")

    def test_reporter_cannot_create_operator_internal_note_by_tampering(self):
        ticket = Ticket.objects.create(
            title="No hidden reporter notes",
            description="Reporter-visible details.",
            reporter=self.reporter,
        )
        client = Client()
        client.force_login(self.reporter)

        response = client.post(
            reverse("ticket-add-message", kwargs={"pk": ticket.pk}),
            {
                "body": "This must stay reporter-visible.",
                "is_operator_note": "1",
            },
        )

        message = ticket.messages.get()
        reporter_detail = client.get(reverse("ticket-detail", kwargs={"pk": ticket.pk}))
        self.assertRedirects(response, reverse("ticket-detail", kwargs={"pk": ticket.pk}))
        self.assertFalse(message.is_operator_note)
        self.assertContains(reporter_detail, "This must stay reporter-visible.")

    def test_thread_message_email_respects_reporter_preferences(self):
        self.reporter.email = "reporter@example.test"
        self.reporter.save(update_fields=["email"])
        NotificationPreference.objects.create(user=self.reporter, email_on_thread_message=False)
        ticket = Ticket.objects.create(
            title="Muted thread",
            description="Reporter does not want thread mail.",
            reporter=self.reporter,
        )
        client = Client()
        client.force_login(self.operator)

        response = client.post(
            reverse("ticket-add-message", kwargs={"pk": ticket.pk}),
            {"body": "Operator reply."},
        )

        self.assertRedirects(response, reverse("ticket-detail", kwargs={"pk": ticket.pk}))
        self.assertEqual(len(mail.outbox), 0)

    def test_status_email_respects_reporter_preferences(self):
        self.reporter.email = "reporter@example.test"
        self.reporter.save(update_fields=["email"])
        NotificationPreference.objects.create(user=self.reporter, email_on_status_change=False)
        ticket = Ticket.objects.create(
            title="Muted status",
            description="Reporter does not want status mail.",
            reporter=self.reporter,
        )
        client = Client()
        client.force_login(self.operator)

        response = client.post(
            reverse("operator-update", kwargs={"pk": ticket.pk}),
            {
                "status": TicketStatus.IN_PROGRESS,
                "operator": self.operator.pk,
                "incident_reference": "",
                "engineering_reference": "",
                "note": "Started investigation.",
            },
        )

        self.assertRedirects(response, reverse("ticket-detail", kwargs={"pk": ticket.pk}))
        self.assertEqual(len(mail.outbox), 0)

    def test_operator_can_promote_ticket_to_openclaw_workspace_incident(self):
        with TemporaryDirectory() as workspace, TemporaryDirectory() as media:
            workspace_root = Path(workspace)
            media_root = Path(media)
            (workspace_root / "incidents").mkdir()
            (workspace_root / "incidents" / "INDEX.md").write_text(
                "# Incident Index\n\n## Active\n\n## Recently Resolved\n",
                encoding="utf-8",
            )
            client = Client()
            client.force_login(self.operator)

            with override_settings(OPENCLAW_WORKSPACE_ROOT=workspace_root, MEDIA_ROOT=media_root):
                ticket = Ticket.objects.create(
                    title="Runtime upload failure",
                    reporter=self.reporter,
                    affected_system=self.system,
                    impact="high",
                    issue_summary="Uploads fail after the first screenshot.",
                    reproduction_steps="1. Open node.\n2. Upload screenshots.",
                    expected_outcome="All screenshots upload.",
                    actual_outcome="The first upload succeeds, then the node disconnects.",
                )
                Attachment.objects.create(
                    ticket=ticket,
                    uploaded_by=self.reporter,
                    file=SimpleUploadedFile("runtime.log", b"boom", content_type="text/plain"),
                    original_name="runtime.log",
                    content_type="text/plain",
                    size_bytes=4,
                )
                response = client.post(
                    reverse("ticket-create-operational-incident", kwargs={"pk": ticket.pk}),
                    self.incident_classification_data(),
                )

            ticket.refresh_from_db()
            incident = OperationalIncident.objects.get(ticket=ticket)
            incident_path = workspace_root / incident.path
            evidence_dir = workspace_root / incident.evidence_path
            copied_evidence = list(evidence_dir.glob("ticket-attachment-*-runtime.log"))
            incident_text = incident_path.read_text(encoding="utf-8")
            index_text = (workspace_root / "incidents" / "INDEX.md").read_text(encoding="utf-8")

            self.assertRedirects(response, reverse("ticket-detail", kwargs={"pk": ticket.pk}))
            self.assertEqual(ticket.incident_reference, incident.reference)
            self.assertEqual(incident.scope, "openclaw-local")
            self.assertEqual(incident.risk, "high")
            self.assertEqual(incident.p_level, "P2")
            self.assertEqual(incident.human_input_required, "decision")
            self.assertTrue(incident.reference.startswith("INC-"))
            self.assertTrue(incident_path.exists())
            self.assertEqual(len(copied_evidence), 1)
            self.assertEqual(copied_evidence[0].read_bytes(), b"boom")
            self.assertEqual(incident.metadata["copied_attachments"][0]["original_name"], "runtime.log")
            self.assertEqual(
                incident.metadata["copied_attachments"][0]["evidence_path"],
                str(copied_evidence[0].relative_to(workspace_root)),
            )
            self.assertIn("Runtime upload failure", incident_text)
            self.assertIn("Scope: openclaw-local", incident_text)
            self.assertIn("P-Level: P2", incident_text)
            self.assertIn("Human input required: decision", incident_text)
            self.assertIn("Runtime failures need active operator triage.", incident_text)
            self.assertIn("runtime.log", incident_text)
            self.assertIn(str(copied_evidence[0].relative_to(workspace_root)), incident_text)
            self.assertIn(incident.reference, index_text)
            self.assertIn("P2/high/private-channel", index_text)
            self.assertTrue(
                LifecycleEvent.objects.filter(
                    ticket=ticket,
                    note__contains=f"Linked OpenClaw workspace incident {incident.reference} (P2/high).",
                ).exists()
            )

    def test_operational_incident_creation_is_operator_only_and_idempotent(self):
        with TemporaryDirectory() as workspace:
            workspace_root = Path(workspace)
            ticket = Ticket.objects.create(
                title="One incident only",
                description="Promote once.",
                reporter=self.reporter,
            )
            reporter_client = Client()
            reporter_client.force_login(self.reporter)
            operator_client = Client()
            operator_client.force_login(self.operator)

            with override_settings(OPENCLAW_WORKSPACE_ROOT=workspace_root):
                reporter_client.post(
                    reverse("ticket-create-operational-incident", kwargs={"pk": ticket.pk}),
                    self.incident_classification_data(),
                )
                first = operator_client.post(
                    reverse("ticket-create-operational-incident", kwargs={"pk": ticket.pk}),
                    self.incident_classification_data(),
                )
                second = operator_client.post(
                    reverse("ticket-create-operational-incident", kwargs={"pk": ticket.pk}),
                    self.incident_classification_data() | {"risk": "critical", "p_level": "P1"},
                )

            self.assertEqual(first.status_code, 302)
            self.assertEqual(second.status_code, 302)
            self.assertEqual(OperationalIncident.objects.filter(ticket=ticket).count(), 1)
            self.assertEqual(LifecycleEvent.objects.filter(ticket=ticket).count(), 1)

    def test_workspace_incident_sync_updates_ticket_status(self):
        with TemporaryDirectory() as workspace:
            workspace_root = Path(workspace)
            (workspace_root / "incidents").mkdir()
            (workspace_root / "incidents" / "INDEX.md").write_text(
                "# Incident Index\n\n## Active\n\n## Recently Resolved\n",
                encoding="utf-8",
            )
            ticket = Ticket.objects.create(
                title="Sync incident status",
                description="Workspace status should flow back.",
                reporter=self.reporter,
            )
            incident = OperationalIncident.objects.create(
                ticket=ticket,
                backend="openclaw_workspace",
                reference="INC-2026-0001",
                title=ticket.title,
                status="intake",
                path="incidents/active/INC-2026-0001-sync.md",
                created_by=self.operator,
            )
            incident_path = workspace_root / incident.path
            incident_path.parent.mkdir(parents=True)
            incident_path.write_text("# INC-2026-0001 Sync\n\nStatus: in progress\n", encoding="utf-8")
            output = StringIO()

            with override_settings(OPENCLAW_WORKSPACE_ROOT=workspace_root):
                call_command("sync_workspace_incidents", stdout=output)

            incident.refresh_from_db()
            ticket.refresh_from_db()
            event = LifecycleEvent.objects.get(ticket=ticket)
            self.assertEqual(incident.status, "in_progress")
            self.assertEqual(ticket.status, TicketStatus.IN_PROGRESS)
            self.assertEqual(event.previous_status, TicketStatus.RECEIVED)
            self.assertEqual(event.new_status, TicketStatus.IN_PROGRESS)
            self.assertIn("Synced OpenClaw workspace incident INC-2026-0001", event.note)
            self.assertIn("1 ticket status row(s) changed", output.getvalue())

    def test_workspace_incident_sync_dry_run_does_not_update_rows(self):
        with TemporaryDirectory() as workspace:
            workspace_root = Path(workspace)
            (workspace_root / "incidents").mkdir()
            (workspace_root / "incidents" / "INDEX.md").write_text(
                "# Incident Index\n\n## Active\n\n## Recently Resolved\n",
                encoding="utf-8",
            )
            ticket = Ticket.objects.create(
                title="Dry run sync",
                description="Workspace status should not change rows in dry-run.",
                reporter=self.reporter,
            )
            incident = OperationalIncident.objects.create(
                ticket=ticket,
                backend="openclaw_workspace",
                reference="INC-2026-0002",
                title=ticket.title,
                status="intake",
                path="incidents/active/INC-2026-0002-dry-run.md",
                created_by=self.operator,
            )
            incident_path = workspace_root / incident.path
            incident_path.parent.mkdir(parents=True)
            incident_path.write_text("# INC-2026-0002 Dry run\n\nStatus: fixed\n", encoding="utf-8")
            output = StringIO()

            with override_settings(OPENCLAW_WORKSPACE_ROOT=workspace_root):
                call_command("sync_workspace_incidents", "--dry-run", stdout=output)

            incident.refresh_from_db()
            ticket.refresh_from_db()
            self.assertEqual(incident.status, "intake")
            self.assertEqual(ticket.status, TicketStatus.RECEIVED)
            self.assertFalse(LifecycleEvent.objects.filter(ticket=ticket).exists())
            self.assertIn("1 incident status row(s) would change", output.getvalue())

    def test_invalid_operational_incident_classification_is_rejected(self):
        with TemporaryDirectory() as workspace:
            ticket = Ticket.objects.create(
                title="Bad classification",
                description="Tampered form.",
                reporter=self.reporter,
            )
            client = Client()
            client.force_login(self.operator)

            with override_settings(OPENCLAW_WORKSPACE_ROOT=Path(workspace)):
                response = client.post(
                    reverse("ticket-create-operational-incident", kwargs={"pk": ticket.pk}),
                    self.incident_classification_data() | {"p_level": "P99"},
                )

            self.assertRedirects(response, reverse("ticket-detail", kwargs={"pk": ticket.pk}))
            self.assertFalse(OperationalIncident.objects.filter(ticket=ticket).exists())

    def test_operations_agent_api_requires_valid_bearer_token_and_scope(self):
        response = Client().get(reverse("api-ticket-detail", kwargs={"pk": 1}))

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["error"], "Missing or invalid bearer token.")

        _, raw_token = self.issue_agent_token(user=self.reporter, scopes=[OperationsAgentScope.TICKETS_CREATE])
        response = Client().get(
            reverse("api-ticket-detail", kwargs={"pk": 1}),
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 403)
        self.assertIn(OperationsAgentScope.TICKETS_READ, response.json()["error"])

    def test_operations_agent_api_can_create_and_read_ticket(self):
        department = Department.objects.create(name="Operations", slug="operations")
        intake_field = DepartmentIntakeField.objects.create(
            department=department,
            label="Monitor name",
            slug="monitor-name",
            is_required=True,
        )
        self.system.default_department = department
        self.system.save(update_fields=["default_department"])
        agent_token, raw_token = self.issue_agent_token(
            user=self.reporter,
            scopes=[OperationsAgentScope.TICKETS_CREATE, OperationsAgentScope.TICKETS_READ],
        )
        payload = {
            "title": "API submitted incident",
            "affected_system": "openclaw-runtime",
            "impact": "high",
            "issue_summary": "Agent detected a failing runtime check.",
            "reproduction_steps": "1. Run health check.\n2. Observe failure.",
            "expected_outcome": "Runtime check passes.",
            "actual_outcome": "Runtime check failed.",
            "additional_context": "Raised by an operations-agent API token.",
            f"department_intake_{intake_field.pk}": "gateway-health",
        }

        response = Client().post(
            reverse("api-ticket-create"),
            data=json.dumps(payload),
            **self.api_headers(raw_token),
        )

        ticket = Ticket.objects.get(title="API submitted incident")
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["ticket"]["id"], ticket.pk)
        self.assertEqual(ticket.reporter, self.reporter)
        self.assertEqual(ticket.affected_system, self.system)
        self.assertEqual(ticket.intake_field_values["monitor-name"]["value"], "gateway-health")
        self.assertEqual(ticket.messages.get().author, self.reporter)

        detail = Client().get(
            reverse("api-ticket-detail", kwargs={"pk": ticket.pk}),
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        agent_token.refresh_from_db()
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["ticket"]["affected_system"], "openclaw-runtime")
        self.assertEqual(detail.json()["ticket"]["intake_field_values"]["monitor-name"]["value"], "gateway-health")
        self.assertEqual(detail.json()["ticket"]["sla"]["state"], "on_track")
        self.assertIsNotNone(detail.json()["ticket"]["sla"]["response_due_at"])
        self.assertEqual(detail.json()["messages"][0]["body"], ticket.description)
        self.assertIsNotNone(agent_token.last_used_at)

    def test_operations_agent_api_rejects_hidden_system_tampering(self):
        private_system = System.objects.create(name="Private Lab", slug="private-lab")
        private_system.visible_to_users.add(self.other_reporter)
        _, raw_token = self.issue_agent_token(user=self.reporter, scopes=[OperationsAgentScope.TICKETS_CREATE])

        response = Client().post(
            reverse("api-ticket-create"),
            data=json.dumps(
                {
                    "title": "Hidden system API report",
                    "affected_system": "private-lab",
                    "impact": "medium",
                    "issue_summary": "Tampered hidden system.",
                    "reproduction_steps": "1. Post API payload.",
                    "expected_outcome": "System is rejected.",
                    "actual_outcome": "Attempted hidden system.",
                }
            ),
            **self.api_headers(raw_token),
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("affected_system", response.json()["errors"])
        self.assertFalse(Ticket.objects.filter(title="Hidden system API report").exists())

    def test_operations_agent_api_can_message_update_and_promote_incident(self):
        with TemporaryDirectory() as workspace, TemporaryDirectory() as media:
            workspace_root = Path(workspace)
            media_root = Path(media)
            ticket = Ticket.objects.create(
                title="API lifecycle ticket",
                description="Agent-managed ticket.",
                reporter=self.reporter,
                affected_system=self.system,
            )
            _, raw_token = self.issue_agent_token(
                user=self.operator,
                scopes=[
                    OperationsAgentScope.TICKETS_READ,
                    OperationsAgentScope.TICKETS_MESSAGE,
                    OperationsAgentScope.TICKETS_UPDATE,
                    OperationsAgentScope.INCIDENTS_PROMOTE,
                ],
            )

            message = Client().post(
                reverse("api-ticket-message", kwargs={"pk": ticket.pk}),
                data=json.dumps({"body": "Agent added an internal note.", "is_operator_note": True}),
                **self.api_headers(raw_token),
            )
            update = Client().post(
                reverse("api-ticket-update", kwargs={"pk": ticket.pk}),
                data=json.dumps(
                    {
                        "status": TicketStatus.IN_PROGRESS,
                        "operator": "operator",
                        "engineering_reference": "api-check",
                        "note": "Agent moved ticket into active triage.",
                    }
                ),
                **self.api_headers(raw_token),
            )

            with override_settings(OPENCLAW_WORKSPACE_ROOT=workspace_root, MEDIA_ROOT=media_root):
                Attachment.objects.create(
                    ticket=ticket,
                    uploaded_by=self.reporter,
                    file=SimpleUploadedFile("api.log", b"api boom", content_type="text/plain"),
                    original_name="api.log",
                    content_type="text/plain",
                    size_bytes=8,
                )
                promote = Client().post(
                    reverse("api-ticket-promote-incident", kwargs={"pk": ticket.pk}),
                    data=json.dumps(self.incident_classification_data()),
                    **self.api_headers(raw_token),
                )

            ticket.refresh_from_db()
            incident = OperationalIncident.objects.get(ticket=ticket)
            self.assertEqual(message.status_code, 201)
            self.assertTrue(message.json()["message"]["is_operator_note"])
            self.assertEqual(update.status_code, 200)
            self.assertEqual(ticket.status, TicketStatus.IN_PROGRESS)
            self.assertEqual(ticket.operator, self.operator)
            self.assertEqual(promote.status_code, 201)
            self.assertEqual(promote.json()["incident"]["reference"], incident.reference)
            self.assertTrue((workspace_root / incident.path).exists())
            self.assertTrue(LifecycleEvent.objects.filter(ticket=ticket, actor=self.operator).exists())

    def test_operations_agent_api_staff_actions_require_staff_user(self):
        ticket = Ticket.objects.create(
            title="Reporter token cannot operate",
            description="No operator powers.",
            reporter=self.reporter,
        )
        _, raw_token = self.issue_agent_token(user=self.reporter, scopes=[OperationsAgentScope.TICKETS_UPDATE])

        response = Client().post(
            reverse("api-ticket-update", kwargs={"pk": ticket.pk}),
            data=json.dumps({"status": TicketStatus.IN_PROGRESS}),
            **self.api_headers(raw_token),
        )

        ticket.refresh_from_db()
        self.assertEqual(response.status_code, 403)
        self.assertEqual(ticket.status, TicketStatus.RECEIVED)

    def test_create_operations_agent_token_command_outputs_token_once(self):
        output = StringIO()

        call_command(
            "create_operations_agent_token",
            "test-agent",
            "--user",
            "operator",
            "--scope",
            OperationsAgentScope.TICKETS_READ,
            stdout=output,
        )

        token = OperationsAgentToken.objects.get(name="test-agent")
        text = output.getvalue()
        raw_token = text.strip().splitlines()[-1]
        self.assertTrue(raw_token.startswith("orc_agent_"))
        self.assertEqual(token.prefix, OperationsAgentToken.prefix_from_raw_token(raw_token))
        self.assertTrue(token.token_matches(raw_token))
        self.assertNotIn(raw_token, token.token_hash)

    def test_seed_demo_creates_department_workflow_reference_data(self):
        output = StringIO()

        call_command("seed_demo", stdout=output)
        call_command("seed_demo", stdout=StringIO())

        departments = Department.objects.in_bulk(field_name="slug")
        self.assertEqual(set(departments), {"admin", "hardware", "operations", "security", "software"})
        for department in departments.values():
            self.assertTrue(department.operator_groups.exists())
            self.assertEqual(department.workflow_templates.count(), 1)
            self.assertGreaterEqual(department.intake_fields.count(), 3)
            self.assertGreaterEqual(department.workflow_templates.get().checklist_item_templates.count(), 3)

        openclaw = System.objects.get(slug="openclaw-runtime")
        self.assertEqual(openclaw.default_department.slug, "operations")
        self.assertEqual(openclaw.default_workflow_template.name, "Operations outage triage")
        self.assertTrue(System.objects.filter(slug="security-events", default_department__slug="security").exists())
        self.assertTrue(System.objects.filter(slug="software-products", default_department__slug="software").exists())
        self.assertTrue(System.objects.filter(slug="hardware-devices", default_department__slug="hardware").exists())
        self.assertTrue(System.objects.filter(slug="admin-services", default_department__slug="admin").exists())
        self.assertEqual(Department.objects.count(), 5)
        self.assertEqual(WorkflowTemplate.objects.count(), 5)
        self.assertEqual(Ticket.objects.count(), 2)
        self.assertIn("Demo data ready.", output.getvalue())
