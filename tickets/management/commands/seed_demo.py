from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management.base import BaseCommand
from django.utils import timezone

from tickets.models import (
    Department,
    DepartmentIntakeField,
    DepartmentIntakeFieldType,
    ImpactLevel,
    KnowledgeBaseArticle,
    KnowledgeBaseAudience,
    System,
    Ticket,
    TicketKnowledgeBaseLink,
    TicketMessage,
    TicketStatus,
    WorkflowChecklistItemTemplate,
    WorkflowTemplate,
)


class Command(BaseCommand):
    help = "Create local demo users, systems, and sample tickets."

    def handle(self, *args, **options):
        User = get_user_model()
        operator, _ = User.objects.update_or_create(
            username="operator",
            defaults={"email": "operator@example.invalid", "is_staff": True, "is_superuser": True},
        )
        operator.set_password("operator")
        operator.save()

        reporter, _ = User.objects.update_or_create(
            username="reporter",
            defaults={"email": "reporter@example.invalid", "is_staff": False},
        )
        reporter.set_password("reporter")
        reporter.save()

        workflow_data = {
            "security": {
                "department": "Security",
                "group": "Security Operators",
                "workflow": "Security incident triage",
                "summary": "Classify exposure, contain the issue, preserve evidence, and verify remediation.",
                "impact": ImpactLevel.HIGH,
                "incident_expected": True,
                "checklist": [
                    ("Classify exposure and access level", "Confirm what data, credentials, or systems may be exposed."),
                    ("Contain active exposure", "Disable tokens, block access, or isolate affected assets."),
                    ("Preserve evidence", "Keep timestamps, logs, request IDs, and affected principals."),
                    ("Verify remediation", "Confirm the exposure is closed before resolving."),
                ],
                "intake": [
                    ("Affected asset", "affected-asset", DepartmentIntakeFieldType.TEXT, "", True),
                    (
                        "Suspected exposure",
                        "suspected-exposure",
                        DepartmentIntakeFieldType.SELECT,
                        "No data exposed\nInternal data\nCustomer data\nCredential or token",
                        True,
                    ),
                    ("First seen", "first-seen", DepartmentIntakeFieldType.TEXT, "", False),
                ],
            },
            "software": {
                "department": "Software",
                "group": "Software Operators",
                "workflow": "Software bug triage",
                "summary": "Reproduce the issue, identify the affected version, and connect repair work.",
                "impact": ImpactLevel.MEDIUM,
                "incident_expected": False,
                "checklist": [
                    ("Confirm affected version", "Record version, branch, build, or deployment identifier."),
                    ("Reproduce or capture failure evidence", "Collect enough detail to confirm expected versus actual behaviour."),
                    ("Link engineering work", "Attach issue, PR, or release reference before closing."),
                ],
                "intake": [
                    ("Environment", "environment", DepartmentIntakeFieldType.SELECT, "Production\nStaging\nDevelopment", True),
                    ("Version or commit", "version-or-commit", DepartmentIntakeFieldType.TEXT, "", False),
                    ("Regression suspected", "regression-suspected", DepartmentIntakeFieldType.CHECKBOX, "", False),
                ],
            },
            "operations": {
                "department": "Operations",
                "group": "Operations Operators",
                "workflow": "Operations outage triage",
                "summary": "Check monitoring, scope the outage, and restore service safely.",
                "impact": ImpactLevel.HIGH,
                "incident_expected": True,
                "checklist": [
                    ("Check monitoring and alerts", "Compare report timing against monitoring and logs."),
                    ("Identify blast radius", "Determine affected users, systems, and dependent services."),
                    ("Record mitigation", "Capture what restored service and any follow-up risk."),
                ],
                "intake": [
                    ("Service or host", "service-or-host", DepartmentIntakeFieldType.TEXT, "", True),
                    ("Observed start time", "observed-start-time", DepartmentIntakeFieldType.TEXT, "", False),
                    ("User-facing outage", "user-facing-outage", DepartmentIntakeFieldType.CHECKBOX, "", False),
                ],
            },
            "hardware": {
                "department": "Hardware",
                "group": "Hardware Operators",
                "workflow": "Hardware support triage",
                "summary": "Identify the device, confirm location, and decide repair or replacement.",
                "impact": ImpactLevel.MEDIUM,
                "incident_expected": False,
                "checklist": [
                    ("Identify device", "Record serial, asset tag, or model."),
                    ("Confirm physical state", "Check power, cabling, network, and visible damage."),
                    ("Decide repair path", "Assign repair, replacement, or monitoring follow-up."),
                ],
                "intake": [
                    ("Device serial or asset tag", "device-serial", DepartmentIntakeFieldType.TEXT, "", True),
                    ("Location", "location", DepartmentIntakeFieldType.TEXT, "", True),
                    ("Safety concern", "safety-concern", DepartmentIntakeFieldType.CHECKBOX, "", False),
                ],
            },
            "admin": {
                "department": "Admin",
                "group": "Admin Operators",
                "workflow": "Admin request triage",
                "summary": "Confirm request type, approvals, and completion evidence.",
                "impact": ImpactLevel.LOW,
                "incident_expected": False,
                "checklist": [
                    ("Confirm requester and approval", "Verify the request is authorized."),
                    ("Complete requested change", "Apply the account, access, billing, or record update."),
                    ("Record completion note", "Leave enough detail for later audit."),
                ],
                "intake": [
                    ("Request type", "request-type", DepartmentIntakeFieldType.SELECT, "Access\nAccount\nBilling\nRecords\nOther", True),
                    ("Approver", "approver", DepartmentIntakeFieldType.TEXT, "", False),
                    ("Due date", "due-date", DepartmentIntakeFieldType.TEXT, "", False),
                ],
            },
        }
        workflows = {}
        for slug, data in workflow_data.items():
            group, _ = Group.objects.get_or_create(name=data["group"])
            group.user_set.add(operator)
            department, _ = Department.objects.update_or_create(
                slug=slug,
                defaults={
                    "name": data["department"],
                    "description": data["summary"],
                    "is_active": True,
                },
            )
            department.operator_groups.add(group)
            workflow, _ = WorkflowTemplate.objects.update_or_create(
                department=department,
                name=data["workflow"],
                defaults={
                    "summary": data["summary"],
                    "default_impact": data["impact"],
                    "incident_promotion_expected": data["incident_expected"],
                    "is_active": True,
                },
            )
            for sort_order, (title, description) in enumerate(data["checklist"], start=1):
                WorkflowChecklistItemTemplate.objects.update_or_create(
                    workflow_template=workflow,
                    title=title,
                    defaults={
                        "description": description,
                        "blocks_closure": True,
                        "sort_order": sort_order * 10,
                    },
                )
            for sort_order, (label, field_slug, field_type, choices, is_required) in enumerate(data["intake"], start=1):
                DepartmentIntakeField.objects.update_or_create(
                    department=department,
                    slug=field_slug,
                    defaults={
                        "label": label,
                        "field_type": field_type,
                        "choices": choices,
                        "is_required": is_required,
                        "is_active": True,
                        "sort_order": sort_order * 10,
                    },
                )
            workflows[slug] = workflow

        def demo_system(slug, name, description, workflow_slug):
            workflow = workflows[workflow_slug]
            system, _ = System.objects.update_or_create(
                slug=slug,
                defaults={
                    "name": name,
                    "description": description,
                    "default_department": workflow.department,
                    "default_workflow_template": workflow,
                    "is_active": True,
                },
            )
            return system

        openclaw = demo_system(
            "openclaw-runtime",
            "OpenClaw Runtime",
            "Core OpenClaw runtime services.",
            "operations",
        )
        lab = demo_system(
            "redshield-lab",
            "Operations Lab",
            "Internal operations lab systems.",
            "operations",
        )
        demo_system("security-events", "Security Events", "Credential, access, and data-exposure reports.", "security")
        demo_system("software-products", "Software Products", "Application defects and release regressions.", "software")
        demo_system("hardware-devices", "Hardware Devices", "Physical devices, peripherals, and lab equipment.", "hardware")
        demo_system("admin-services", "Admin Services", "Access, account, billing, and records requests.", "admin")

        ticket, created = Ticket.objects.get_or_create(
            title="OpenClaw node intermittently disconnects",
            reporter=reporter,
            defaults={
                "issue_summary": "The Android node drops offline during attachment uploads.",
                "reproduction_steps": "1. Open the Android node.\n2. Upload several screenshots.\n3. Watch the gateway status.",
                "expected_outcome": "The node stays online until the upload completes.",
                "actual_outcome": "The node disconnects before the upload finishes.",
                "additional_context": "Happened twice during demo intake testing.",
                "affected_system": openclaw,
                "impact": ImpactLevel.HIGH,
                "status": TicketStatus.TRIAGED,
                "operator": operator,
                "incident_reference": "INC-DEMO-0001",
            },
        )
        if not ticket.department:
            ticket.department = openclaw.default_department
            ticket.workflow_template = openclaw.default_workflow_template
            ticket.save()
        ticket.generate_workflow_checklist()
        if not ticket.first_response_at:
            ticket.first_response_at = timezone.now()
            ticket.save(update_fields=["first_response_at", "updated_at"])
        if created:
            TicketMessage.objects.create(
                ticket=ticket,
                author=reporter,
                body="The node disconnected twice while uploading screenshots.",
            )
            TicketMessage.objects.create(
                ticket=ticket,
                author=operator,
                body="Triage complete. Checking gateway logs and upload retry behaviour.",
            )

        article, _ = KnowledgeBaseArticle.objects.get_or_create(
            slug="android-node-upload-disconnects",
            defaults={
                "title": "Android node disconnects during uploads",
                "summary": "Initial triage steps for node disconnects during multi-file evidence uploads.",
                "body": (
                    "Check gateway logs, node battery/network state, and upload retry behaviour. "
                    "Capture timestamps and request IDs before restarting the node."
                ),
                "audience": KnowledgeBaseAudience.ALL_INTERNAL,
                "tags": "node, uploads, gateway",
                "is_published": True,
                "created_by": operator,
                "updated_by": operator,
            },
        )
        article.systems.add(openclaw)
        TicketKnowledgeBaseLink.objects.get_or_create(
            ticket=ticket,
            article=article,
            defaults={"note": "Demo known issue.", "linked_by": operator},
        )

        lab_ticket, _ = Ticket.objects.get_or_create(
            title="Lab dashboard shows stale status",
            reporter=reporter,
            defaults={
                "issue_summary": "The dashboard says the lab host is down, but SSH works.",
                "reproduction_steps": "1. Open the lab dashboard.\n2. Check the host status.\n3. SSH to the same host.",
                "expected_outcome": "Dashboard status matches direct host availability.",
                "actual_outcome": "Dashboard says down while SSH succeeds.",
                "affected_system": lab,
                "impact": ImpactLevel.MEDIUM,
                "status": TicketStatus.RECEIVED,
            },
        )
        if not lab_ticket.department:
            lab_ticket.department = lab.default_department
            lab_ticket.workflow_template = lab.default_workflow_template
            lab_ticket.save()
        lab_ticket.generate_workflow_checklist()

        self.stdout.write(self.style.SUCCESS("Demo data ready."))
        self.stdout.write("operator / operator has staff/admin access.")
        self.stdout.write("reporter / reporter has reporter access.")
