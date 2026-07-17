from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from tickets.models import OperationsAgentScope, OperationsAgentToken


class Command(BaseCommand):
    help = "Create a scoped bearer token for an operations agent service account."

    def add_arguments(self, parser):
        parser.add_argument("name", help="Human-readable token name.")
        parser.add_argument("--user", required=True, help="Django username the token acts as.")
        parser.add_argument(
            "--scope",
            action="append",
            dest="scopes",
            help="Allowed scope. Repeat for multiple scopes. Use --all-scopes for the full API surface.",
        )
        parser.add_argument("--all-scopes", action="store_true", help="Grant all operations-agent API scopes.")

    def handle(self, *args, **options):
        User = get_user_model()
        try:
            user = User.objects.get(username=options["user"])
        except User.DoesNotExist as exc:
            raise CommandError(f"Unknown user: {options['user']}") from exc

        valid_scopes = {choice.value for choice in OperationsAgentScope}
        scopes = valid_scopes if options["all_scopes"] else set(options["scopes"] or [])
        unknown_scopes = scopes - valid_scopes
        if unknown_scopes:
            raise CommandError(f"Unknown scope(s): {', '.join(sorted(unknown_scopes))}")
        if not scopes:
            raise CommandError("At least one --scope or --all-scopes is required.")

        _, raw_token = OperationsAgentToken.issue(
            name=options["name"],
            user=user,
            scopes=sorted(scopes),
        )
        self.stdout.write(self.style.SUCCESS("Operations agent token created. Store it now; it is shown once."))
        self.stdout.write(raw_token)
