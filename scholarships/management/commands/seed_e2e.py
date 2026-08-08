"""Deterministic fixtures for the Playwright suite.

Idempotent: safe to run against an existing e2e database. The credentials are
throwaway values for the CI sqlite database only - they never exist in a real
environment.
"""

from datetime import timedelta

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from django.utils import timezone

from scholarships.models import Admin, Scholarship, Student

ADMIN_USERNAME = "e2e-admin"
ADMIN_PASSWORD = "E2eAdminPass123"
STUDENT_USERNAME = "e2e-student"
STUDENT_PASSWORD = "E2eStudentPass123"


class Command(BaseCommand):
    help = "Create the accounts and scholarships the e2e suite expects."

    def handle(self, *args, **options):
        admin_user, _ = User.objects.update_or_create(
            username=ADMIN_USERNAME,
            defaults={"email": "e2e-admin@example.com", "is_staff": True},
        )
        admin_user.set_password(ADMIN_PASSWORD)
        admin_user.save()
        Admin.objects.update_or_create(
            user=admin_user, defaults={"is_super_admin": True}
        )

        student_user, _ = User.objects.update_or_create(
            username=STUDENT_USERNAME,
            defaults={"email": "e2e-student@example.com", "first_name": "E2e"},
        )
        student_user.set_password(STUDENT_PASSWORD)
        student_user.save()
        Student.objects.update_or_create(
            user=student_user,
            defaults={
                "phone": "",
                "country_of_citizenship": "Liberia",
                "country_of_residence": "Ghana",
                "education_level": "undergraduate",
            },
        )

        Scholarship.objects.update_or_create(
            name="E2E Test Scholarship",
            defaults={
                "description": "Seeded by seed_e2e for the Playwright suite.",
                "deadline": timezone.now().date() + timedelta(days=60),
                "host_country": "United Kingdom",
                "benefits": "Tuition\nStipend",
                "eligibility": "Seeded eligibility",
                "degree_level": "Masters",
                "link": "https://example.com/apply",
                "author": "myScholy",
                "is_active": True,
            },
        )

        self.stdout.write(self.style.SUCCESS("e2e fixtures ready"))
