from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from tickets.models import Attachment, TicketStatus


class Command(BaseCommand):
    help = "Remove retained ticket attachments from closed tickets after the retention window."

    def add_arguments(self, parser):
        parser.add_argument(
            "--days",
            type=int,
            default=90,
            help="Retain closed-ticket attachments for this many days. Default: 90.",
        )
        parser.add_argument(
            "--delete",
            action="store_true",
            help="Actually delete matching attachment files and database rows. Otherwise dry-run only.",
        )

    def handle(self, *args, **options):
        retention_days = options["days"]
        if retention_days < 1:
            raise CommandError("--days must be 1 or greater.")

        cutoff = timezone.now() - timedelta(days=retention_days)
        candidates = Attachment.objects.select_related("ticket").filter(
            ticket__status=TicketStatus.CLOSED,
            ticket__updated_at__lt=cutoff,
        )
        delete = options["delete"]
        action = "Deleting" if delete else "Would delete"
        count = 0
        total_bytes = 0
        missing_files = 0

        for attachment in candidates.iterator():
            count += 1
            total_bytes += attachment.size_bytes
            file_name = attachment.file.name
            exists = bool(file_name and attachment.file.storage.exists(file_name))
            if not exists:
                missing_files += 1
            self.stdout.write(
                f"{action} attachment #{attachment.pk} from ticket #{attachment.ticket_id}: "
                f"{attachment.original_name} ({attachment.size_bytes} bytes)"
            )
            if delete:
                if exists:
                    attachment.file.delete(save=False)
                attachment.delete()

        mode = "deleted" if delete else "matched"
        self.stdout.write(
            self.style.SUCCESS(
                f"{count} attachment(s) {mode}; {total_bytes} byte(s) total; "
                f"{missing_files} missing file(s)."
            )
        )
        if not delete:
            self.stdout.write("Dry run only. Re-run with --delete to remove matching attachments.")
