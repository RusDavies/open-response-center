from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.utils import timezone

from tickets.models import (
    ImpactLevel,
    KnowledgeBaseArticle,
    KnowledgeBaseAudience,
    System,
    Ticket,
    TicketKnowledgeBaseLink,
    TicketMessage,
    TicketStatus,
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

        openclaw, _ = System.objects.get_or_create(
            slug="openclaw-runtime",
            defaults={"name": "OpenClaw Runtime", "description": "Core OpenClaw runtime services."},
        )
        lab, _ = System.objects.get_or_create(
            slug="redshield-lab",
            defaults={"name": "Operations Lab", "description": "Internal operations lab systems."},
        )

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

        Ticket.objects.get_or_create(
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

        self.stdout.write(self.style.SUCCESS("Demo data ready."))
        self.stdout.write("operator / operator has staff/admin access.")
        self.stdout.write("reporter / reporter has reporter access.")
