from django.conf import settings
from django.contrib.auth import get_user_model, login


class TrustedRemoteUserMiddleware:
    """Authenticate users from headers set by a trusted reverse proxy."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if getattr(settings, "ORC_ENABLE_REMOTE_USER_AUTH", False):
            self.authenticate_remote_user(request)
        return self.get_response(request)

    def authenticate_remote_user(self, request) -> None:
        username = self.header_value(request, settings.ORC_REMOTE_USER_HEADER)
        if not username:
            return

        User = get_user_model()
        username_field = User.USERNAME_FIELD
        username_max_length = User._meta.get_field(username_field).max_length
        username = username.strip()
        if not username or len(username) > username_max_length:
            return

        user, created = User.objects.get_or_create(**{username_field: username})
        changed_fields = []
        if created:
            user.set_unusable_password()
            changed_fields.append("password")

        email = self.header_value(request, settings.ORC_REMOTE_USER_EMAIL_HEADER)
        if email and user.email != email:
            user.email = email
            changed_fields.append("email")

        first_name = self.header_value(request, settings.ORC_REMOTE_USER_FIRST_NAME_HEADER)
        if first_name and user.first_name != first_name:
            user.first_name = first_name
            changed_fields.append("first_name")

        last_name = self.header_value(request, settings.ORC_REMOTE_USER_LAST_NAME_HEADER)
        if last_name and user.last_name != last_name:
            user.last_name = last_name
            changed_fields.append("last_name")

        staff_header = settings.ORC_REMOTE_USER_STAFF_HEADER
        if staff_header:
            is_staff = self.header_value(request, staff_header).lower() in {"1", "true", "yes", "on"}
            if user.is_staff != is_staff:
                user.is_staff = is_staff
                changed_fields.append("is_staff")

        if changed_fields:
            user.save(update_fields=changed_fields)

        if not user.is_active:
            return

        if not request.user.is_authenticated or request.user.get_username() != user.get_username():
            login(request, user, backend="django.contrib.auth.backends.ModelBackend")

    def header_value(self, request, header_name: str) -> str:
        if not header_name:
            return ""
        return request.META.get(header_name, "").strip()
