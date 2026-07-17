from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from tickets.incident_adapters import OpenClawWorkspaceIncidentAdapter


class Command(BaseCommand):
    help = "Import status changes from linked OpenClaw workspace incident files."

    def add_arguments(self, parser):
        parser.add_argument(
            "--actor",
            help="Username to record on lifecycle events. Defaults to each incident creator.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report what would change without updating tickets or incident rows.",
        )

    def handle(self, *args, **options):
        actor = None
        if options["actor"]:
            User = get_user_model()
            try:
                actor = User.objects.get(username=options["actor"])
            except User.DoesNotExist as exc:
                raise CommandError(f"Unknown actor username: {options['actor']}") from exc

        results = OpenClawWorkspaceIncidentAdapter().sync_linked_incidents(
            actor=actor,
            dry_run=options["dry_run"],
        )
        changed = 0
        ticket_changed = 0
        for result in results:
            if result.changed:
                changed += 1
            if result.ticket_changed:
                ticket_changed += 1
            action = "Would sync" if options["dry_run"] else "Synced"
            self.stdout.write(
                f"{action} {result.incident.reference}: incident "
                f"{result.previous_incident_status} -> {result.workspace_status}; ticket "
                f"{result.previous_ticket_status} -> {result.new_ticket_status}"
            )

        mode = "would change" if options["dry_run"] else "changed"
        self.stdout.write(
            self.style.SUCCESS(
                f"{len(results)} linked incident(s) checked; {changed} incident status row(s) {mode}; "
                f"{ticket_changed} ticket status row(s) {mode}."
            )
        )
