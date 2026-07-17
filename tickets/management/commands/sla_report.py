from django.core.management.base import BaseCommand, CommandError

from tickets.models import Ticket, TicketStatus


class Command(BaseCommand):
    help = "Report open-ticket SLA state for operators and automation."

    def add_arguments(self, parser):
        parser.add_argument(
            "--breached-only",
            action="store_true",
            help="Show only tickets with a breached response or resolution SLA.",
        )
        parser.add_argument(
            "--fail-on-breach",
            action="store_true",
            help="Exit non-zero when any open ticket has a breached SLA.",
        )

    def handle(self, *args, **options):
        tickets = Ticket.objects.select_related("affected_system", "reporter", "operator").exclude(
            status=TicketStatus.CLOSED
        )
        shown = 0
        breached = 0

        for ticket in tickets.order_by("created_at").iterator():
            sla = ticket.sla_summary
            if sla["state"] == "breached":
                breached += 1
            elif options["breached_only"]:
                continue

            shown += 1
            system = ticket.affected_system.slug if ticket.affected_system else "-"
            operator = ticket.operator.get_username() if ticket.operator else "unassigned"
            self.stdout.write(
                f"#{ticket.pk} {sla['state']} {ticket.get_impact_display()} "
                f"{ticket.get_status_display()} system={system} operator={operator} "
                f"response_due={sla['response_due_at'].isoformat()} "
                f"resolution_due={sla['resolution_due_at'].isoformat()} {ticket.title}"
            )

        self.stdout.write(self.style.SUCCESS(f"{shown} ticket(s) shown; {breached} breached open SLA(s)."))
        if options["fail_on_breach"] and breached:
            raise CommandError(f"{breached} open ticket(s) have breached SLA targets.")
