from django.core.mail import send_mail

from .models import NotificationPreference, Ticket


def email_enabled(user, event: str) -> bool:
    preference, _ = NotificationPreference.objects.get_or_create(user=user)
    if event == "status":
        return preference.email_on_status_change
    if event == "thread":
        return preference.email_on_thread_message
    return True


def notify_ticket_watchers(
    ticket: Ticket,
    subject: str,
    body: str,
    *,
    event: str,
    exclude_user_id: int | None = None,
) -> None:
    recipients = set()
    watchers = [ticket.reporter]
    if ticket.operator:
        watchers.append(ticket.operator)
    for watcher in watchers:
        if watcher.id == exclude_user_id or not watcher.email:
            continue
        if email_enabled(watcher, event):
            recipients.add(watcher.email)
    if recipients:
        send_mail(subject, body, None, sorted(recipients), fail_silently=True)
