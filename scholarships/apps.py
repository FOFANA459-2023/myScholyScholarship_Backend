from django.apps import AppConfig


class ScholarshipsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "scholarships"

    def ready(self):
        # Register cache-invalidation receivers.
        from . import signals  # noqa: F401
