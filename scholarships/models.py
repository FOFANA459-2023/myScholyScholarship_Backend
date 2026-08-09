from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone


class ScholarshipQuerySet(models.QuerySet):
    """Reusable query building blocks so views never hand-roll filters."""

    def active(self):
        return self.filter(is_active=True)

    def open_for_application(self):
        return self.filter(deadline__gte=timezone.now().date())

    def list_fields(self):
        """Trim the payload for list endpoints - description/benefits/eligibility
        are large TEXT columns that no card view ever renders."""
        return self.only(
            "id",
            "name",
            "deadline",
            "host_country",
            "degree_level",
            "author",
            "link",
            "created_at",
            "is_active",
        )


class Scholarship(models.Model):
    name = models.CharField(max_length=255, db_index=True)
    description = models.TextField()
    deadline = models.DateField()
    host_country = models.CharField(max_length=100)
    benefits = models.TextField()
    eligibility = models.TextField()
    degree_level = models.CharField(max_length=100)
    link = models.URLField()
    author = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    objects = ScholarshipQuerySet.as_manager()

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            # Covers the default public listing: active rows, newest first.
            models.Index(
                fields=["is_active", "-created_at"], name="scholarship_active_recent"
            ),
            # Covers the facet filters exposed on the scholarship board.
            models.Index(
                fields=["is_active", "host_country"], name="scholarship_country"
            ),
            models.Index(
                fields=["is_active", "degree_level"], name="scholarship_degree"
            ),
            # Covers "application ongoing" and deadline sorting.
            models.Index(fields=["is_active", "deadline"], name="scholarship_deadline"),
        ]

    def __str__(self):
        return self.name

    @property
    def is_open(self):
        return self.deadline >= timezone.now().date()


class DigestRun(models.Model):
    """One row per full scholarship-digest send.

    The ``send_scholarship_digest`` command refuses to run when a row exists
    inside its minimum interval. Both production servers (Oracle and the
    Render backup) share this database, so the guard holds even if the
    command gets scheduled on more than one machine - the second trigger
    sees the first one's row and skips instead of emailing everyone twice.
    """

    sent_at = models.DateTimeField(auto_now_add=True, db_index=True)
    recipient_count = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["-sent_at"]

    def __str__(self):
        return f"Digest at {self.sent_at:%Y-%m-%d %H:%M} UTC"


class Student(models.Model):
    """A student profile.

    ``country_of_citizenship`` is the old ``nationality`` column renamed: it
    holds the same thing, and pairing it with ``country_of_residence`` under
    matching names makes the two obviously distinct on the signup form. Many
    scholarships key eligibility off citizenship rather than where the
    applicant currently lives, so both are captured.
    """

    class EducationLevel(models.TextChoices):
        HIGH_SCHOOL = "high_school", "High school"
        UNDERGRADUATE = "undergraduate", "Undergraduate"
        GRADUATE = "graduate", "Graduate"

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone = models.CharField(max_length=20, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    country_of_citizenship = models.CharField(max_length=100, blank=True, db_index=True)
    country_of_residence = models.CharField(max_length=100, blank=True, db_index=True)
    education_level = models.CharField(
        max_length=20, choices=EducationLevel.choices, blank=True, db_index=True
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.user.first_name} {self.user.last_name}".strip() or self.user.username


class Admin(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    is_super_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Admin: {self.user.username}"


class ContactMessage(models.Model):
    """Messages submitted from the public contact form and site footer."""

    name = models.CharField(max_length=120)
    email = models.EmailField()
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_handled = models.BooleanField(default=False)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["is_handled", "-created_at"], name="contact_inbox"),
        ]

    def __str__(self):
        return f"{self.name} <{self.email}>"
