import os
from datetime import timedelta
from unittest import mock

from django.conf import settings
from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from .models import (
    Admin,
    ContactMessage,
    DigestRun,
    OutboundMessage,
    Scholarship,
    Student,
)


def make_scholarship(**overrides):
    defaults = {
        "name": "Chevening Scholarship",
        "description": "Fully funded master's study in the UK.",
        "deadline": timezone.now().date() + timedelta(days=30),
        "host_country": "United Kingdom",
        "benefits": "Tuition\nStipend",
        "eligibility": "Bachelor's degree\nTwo years work experience",
        "degree_level": "Masters",
        "link": "https://example.com/apply",
        "author": "myScholy",
    }
    defaults.update(overrides)
    return Scholarship.objects.create(**defaults)


class ScholarshipListTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        make_scholarship(name="Chevening", host_country="United Kingdom")
        make_scholarship(name="Mastercard Foundation", host_country="Rwanda")
        make_scholarship(
            name="Expired Award",
            host_country="Japan",
            deadline=timezone.now().date() - timedelta(days=5),
        )
        make_scholarship(name="Hidden Award", host_country="Japan", is_active=False)

    def test_list_returns_only_live_and_is_paginated(self):
        """The public board shows live rows only: active AND still open.
        Hidden and expired rows both belong to the admin archive."""
        response = self.client.get("/api/scholarships/")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["count"], 2)
        self.assertIn("results", body)
        self.assertIn("total_pages", body)
        names = {row["name"] for row in body["results"]}
        self.assertNotIn("Hidden Award", names)
        self.assertNotIn("Expired Award", names)

    def test_anonymous_cannot_request_archived_view(self):
        body = self.client.get("/api/scholarships/?view=archived").json()
        names = {row["name"] for row in body["results"]}
        self.assertEqual(names, {"Chevening", "Mastercard Foundation"})

    def test_list_payload_omits_large_text_columns(self):
        row = self.client.get("/api/scholarships/").json()["results"][0]
        for field in ("description", "benefits", "eligibility"):
            self.assertNotIn(field, row)

    def test_search_filters_server_side(self):
        body = self.client.get("/api/scholarships/?q=chevening").json()
        self.assertEqual(body["count"], 1)
        self.assertEqual(body["results"][0]["name"], "Chevening")

    def test_country_filter(self):
        # Both Japan rows are archived (one expired, one hidden), so the
        # public board has nothing to show for that country.
        self.assertEqual(
            self.client.get("/api/scholarships/?country=Japan").json()["count"], 0
        )
        self.assertEqual(
            self.client.get("/api/scholarships/?country=Rwanda").json()["count"], 1
        )

    def test_conditional_request_returns_304(self):
        first = self.client.get("/api/scholarships/")
        second = self.client.get("/api/scholarships/", HTTP_IF_NONE_MATCH=first["ETag"])
        self.assertEqual(second.status_code, 304)

    def test_write_invalidates_cache_and_etag(self):
        first = self.client.get("/api/scholarships/")
        make_scholarship(name="Brand New Award")
        second = self.client.get("/api/scholarships/")
        self.assertNotEqual(first["ETag"], second["ETag"])
        self.assertEqual(second.json()["count"], 3)

    def test_facets_endpoint(self):
        """Facets offer the fixed regions and degree buckets, counting the
        live board only - archived rows must not inflate any count."""
        body = self.client.get("/api/scholarships/facets/").json()

        countries = {row["value"]: row["count"] for row in body["countries"]}
        self.assertEqual(
            set(countries),
            {"Africa", "Europe", "Australia", "Asia", "United States", "Canada"},
        )
        # United Kingdom -> Europe, Rwanda -> Africa; both Japan rows are
        # archived so Asia counts nothing.
        self.assertEqual(countries["Europe"], 1)
        self.assertEqual(countries["Africa"], 1)
        self.assertEqual(countries["Asia"], 0)

        degrees = {row["value"]: row["count"] for row in body["degree_levels"]}
        self.assertEqual(
            set(degrees),
            {"Undergraduate", "Graduate", "Postgraduate", "Non-degree"},
        )
        # All live rows are seeded as "Masters" -> Graduate.
        self.assertEqual(degrees["Graduate"], 2)

    def test_region_and_degree_bucket_filters(self):
        """The canonical dropdown values select rows by classification while
        exact stored values (old bookmarked URLs) keep working."""
        self.assertEqual(
            self.client.get("/api/scholarships/?country=Africa").json()["count"], 1
        )
        self.assertEqual(
            self.client.get("/api/scholarships/?country=Europe").json()["count"], 1
        )
        # Both Japan rows are archived, so Asia matches nothing live.
        self.assertEqual(
            self.client.get("/api/scholarships/?country=Asia").json()["count"], 0
        )
        # Seeded degree_level "Masters" classifies as Graduate, not the others.
        self.assertEqual(
            self.client.get("/api/scholarships/?degree=Graduate").json()["count"], 2
        )
        self.assertEqual(
            self.client.get("/api/scholarships/?degree=Undergraduate").json()["count"],
            0,
        )

    def test_hidden_scholarship_is_not_readable_by_id(self):
        hidden = Scholarship.objects.get(name="Hidden Award")
        self.assertEqual(self.client.get(f"/api/scholarships/{hidden.pk}/").status_code, 404)

        visible = Scholarship.objects.get(name="Chevening")
        self.assertEqual(self.client.get(f"/api/scholarships/{visible.pk}/").status_code, 200)

    def test_admin_can_read_hidden_scholarship_by_id(self):
        admin_user = User.objects.create_user(
            username="editor", password="Str0ngPassw0rd!", is_staff=True
        )
        self.client.force_authenticate(admin_user)
        hidden = Scholarship.objects.get(name="Hidden Award")
        self.assertEqual(self.client.get(f"/api/scholarships/{hidden.pk}/").status_code, 200)

    def test_anonymous_cannot_create(self):
        response = self.client.post(
            "/api/scholarships/", {"name": "Nope"}, format="json"
        )
        self.assertIn(response.status_code, (401, 403))

    def test_detail_readable_by_slug(self):
        visible = Scholarship.objects.get(name="Chevening")
        self.assertEqual(visible.slug, "chevening")
        response = self.client.get(f"/api/scholarships/{visible.slug}/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["id"], visible.pk)

    def test_hidden_scholarship_is_not_readable_by_slug(self):
        hidden = Scholarship.objects.get(name="Hidden Award")
        self.assertEqual(
            self.client.get(f"/api/scholarships/{hidden.slug}/").status_code, 404
        )

    def test_slugs_are_unique_and_never_numeric(self):
        first = Scholarship.objects.get(name="Chevening")
        second = make_scholarship(name="Chevening")
        self.assertEqual(second.slug, f"{first.slug}-2")
        numeric = make_scholarship(name="2026")
        self.assertFalse(numeric.slug.isdigit())
        self.assertEqual(
            self.client.get(f"/api/scholarships/{numeric.slug}/").status_code, 200
        )

    def test_list_payload_includes_slug(self):
        row = self.client.get("/api/scholarships/").json()["results"][0]
        self.assertIn("slug", row)
        self.assertTrue(row["slug"])

    def test_social_card_renders_png(self):
        visible = Scholarship.objects.get(name="Chevening")
        response = self.client.get(f"/api/scholarships/{visible.slug}/card.png")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "image/png")
        self.assertTrue(response.content.startswith(b"\x89PNG"))

    def test_social_card_variants(self):
        from io import BytesIO

        from PIL import Image

        visible = Scholarship.objects.get(name="Chevening")
        for variant, size in (("square", (1080, 1080)), ("linkedin", (1200, 627))):
            response = self.client.get(
                f"/api/scholarships/{visible.slug}/card.png?variant={variant}"
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(Image.open(BytesIO(response.content)).size, size)
        # Unknown variants fall back to the wide default rather than erroring.
        response = self.client.get(
            f"/api/scholarships/{visible.slug}/card.png?variant=bogus"
        )
        self.assertEqual(response.status_code, 200)
        from scholarships.social_cards import SIZES

        self.assertEqual(
            Image.open(BytesIO(response.content)).size, SIZES["wide"]
        )

    def test_social_card_hidden_scholarship_404s(self):
        hidden = Scholarship.objects.get(name="Hidden Award")
        self.assertEqual(
            self.client.get(f"/api/scholarships/{hidden.slug}/card.png").status_code,
            404,
        )

    def test_similar_ranks_matching_country_and_degree_first(self):
        target = Scholarship.objects.get(name="Chevening")  # UK, Masters
        make_scholarship(
            name="Rhodes Scholarship", host_country="United Kingdom",
            degree_level="Masters", link="https://example.com/rhodes",
        )
        make_scholarship(
            name="DAAD Grant", host_country="Germany",
            degree_level="Bachelors", link="https://example.com/daad",
        )
        make_scholarship(
            name="Expired UK Award", host_country="United Kingdom",
            degree_level="Masters", link="https://example.com/expired",
            deadline=timezone.now().date() - timedelta(days=1),
        )
        make_scholarship(
            name="Hidden UK Award", host_country="United Kingdom",
            degree_level="Masters", link="https://example.com/hiddenuk",
            is_active=False,
        )

        body = self.client.get(f"/api/scholarships/{target.slug}/similar/").json()
        names = [row["name"] for row in body]
        # Most similar leads; expired, hidden and the scholarship itself
        # never appear; zero-score rows still fill the strip.
        self.assertEqual(names[0], "Rhodes Scholarship")
        self.assertIn("DAAD Grant", names)
        self.assertNotIn("Chevening", names)
        self.assertNotIn("Expired UK Award", names)
        self.assertNotIn("Hidden UK Award", names)
        self.assertLessEqual(len(names), 4)
        self.assertIn("slug", body[0])

    def test_similar_404_for_hidden_scholarship(self):
        hidden = Scholarship.objects.get(name="Hidden Award")
        self.assertEqual(
            self.client.get(f"/api/scholarships/{hidden.slug}/similar/").status_code,
            404,
        )


class AuthTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        User.objects.create_user(
            username="ama", email="ama@example.com", password="Str0ngPassw0rd!"
        )

    def test_login_with_username_and_with_email(self):
        for identifier in ("ama", "ama@example.com"):
            response = self.client.post(
                "/api/auth/login/",
                {"username": identifier, "password": "Str0ngPassw0rd!"},
                format="json",
            )
            self.assertEqual(response.status_code, 200, identifier)
            self.assertIn("access", response.json()["tokens"])

    def test_login_stamps_last_login(self):
        """The custom login bypasses SIMPLE_JWT's UPDATE_LAST_LOGIN hook, so
        it must set last_login itself - the user directory reads it."""
        user = User.objects.get(username="ama")
        self.assertIsNone(user.last_login)
        response = self.client.post(
            "/api/auth/login/",
            {"username": "ama", "password": "Str0ngPassw0rd!"},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        user.refresh_from_db()
        self.assertIsNotNone(user.last_login)

    def test_login_rejects_bad_password(self):
        response = self.client.post(
            "/api/auth/login/", {"username": "ama", "password": "wrong"}, format="json"
        )
        self.assertEqual(response.status_code, 401)

    def test_student_registration_returns_tokens(self):
        response = self.client.post(
            "/api/auth/student/register/",
            {
                "user": {
                    "username": "kofi",
                    "email": "kofi@example.com",
                    "first_name": "Kofi",
                    "last_name": "Mensah",
                    "password": "An0therStr0ng!",
                },
                "phone": "0201234567",
                "country_of_citizenship": "Ghana",
                "country_of_residence": "Ghana",
                "education_level": "undergraduate",
            },
            format="json",
        )
        self.assertEqual(response.status_code, 201, response.content)
        self.assertIn("tokens", response.json())
        self.assertTrue(
            User.objects.get(username="kofi").check_password("An0therStr0ng!")
        )
        student = Student.objects.get(user__username="kofi")
        self.assertEqual(student.country_of_citizenship, "Ghana")
        self.assertEqual(student.education_level, "undergraduate")

    def test_admin_registration_is_not_public(self):
        response = self.client.post(
            "/api/auth/admin/register/",
            {"user": {"username": "sneaky", "password": "An0therStr0ng!"}},
            format="json",
        )
        self.assertIn(response.status_code, (401, 403))


class AdminApiTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.super_admin = User.objects.create_user(
            username="boss",
            password="Str0ngPassw0rd!",
            is_staff=True,
            is_superuser=True,
        )
        Admin.objects.create(user=self.super_admin, is_super_admin=True)
        self.client.force_authenticate(self.super_admin)
        make_scholarship()
        make_scholarship(name="Inactive", is_active=False)

    def test_admin_listing_views(self):
        """Default view matches the live board; archived rows have their own
        view; ``all`` returns everything for the client-side index."""
        self.assertEqual(self.client.get("/api/admin/scholarships/").json()["count"], 1)
        archived = self.client.get("/api/admin/scholarships/?view=archived").json()
        self.assertEqual(archived["count"], 1)
        self.assertEqual(archived["results"][0]["name"], "Inactive")
        self.assertEqual(
            self.client.get("/api/admin/scholarships/?view=all").json()["count"], 2
        )

    def test_repost_reactivates_when_deadline_ahead(self):
        hidden = Scholarship.objects.get(name="Inactive")
        response = self.client.post(f"/api/admin/scholarships/{hidden.pk}/repost/")
        self.assertEqual(response.status_code, 200, response.content)
        hidden.refresh_from_db()
        self.assertTrue(hidden.is_active)
        # The write must invalidate the cached lists immediately.
        self.assertEqual(self.client.get("/api/admin/scholarships/").json()["count"], 2)

    def test_repost_rejected_when_deadline_passed(self):
        expired = make_scholarship(
            name="Too Late",
            is_active=False,
            deadline=timezone.now().date() - timedelta(days=1),
        )
        response = self.client.post(f"/api/admin/scholarships/{expired.pk}/repost/")
        self.assertEqual(response.status_code, 400)
        self.assertIn("deadline", response.json()["error"].lower())
        expired.refresh_from_db()
        self.assertFalse(expired.is_active)

    def test_repost_requires_admin(self):
        scholarship = Scholarship.objects.first()
        anon = APIClient()
        response = anon.post(f"/api/admin/scholarships/{scholarship.pk}/repost/")
        self.assertIn(response.status_code, (401, 403))

    def test_statistics_shape(self):
        body = self.client.get("/api/admin/statistics/").json()
        self.assertEqual(body["total_scholarships"], 2)
        self.assertEqual(body["active_scholarships"], 1)
        self.assertEqual(body["total_admins"], 1)

    def test_statistics_refresh_after_scholarship_write(self):
        """The dashboard mixes user and scholarship numbers; a scholarship
        write must change its ETag and payload, not serve a 304 forever."""
        first = self.client.get("/api/admin/statistics/")
        make_scholarship(name="Fresh Award")
        second = self.client.get("/api/admin/statistics/")
        self.assertNotEqual(first["ETag"], second["ETag"])
        self.assertEqual(second.json()["total_scholarships"], 3)

    def test_admin_roster_has_no_n_plus_one(self):
        """Adding admins must not add queries - the old loop ran one per row."""
        cache.clear()
        with self.assertNumQueries(2):
            self.client.get("/api/admins/")

        for index in range(5):
            staff = User.objects.create_user(
                username=f"staff{index}", password="Str0ngPassw0rd!", is_staff=True
            )
            Admin.objects.create(user=staff)

        cache.clear()
        with self.assertNumQueries(2):
            response = self.client.get("/api/admins/")
        self.assertEqual(len(response.json()), 6)

    def test_super_admin_cannot_delete_self(self):
        response = self.client.delete(f"/api/admins/{self.super_admin.id}/")
        self.assertEqual(response.status_code, 403)

    def test_scholarship_export_streams_live_rows_only(self):
        response = self.client.get("/api/admin/scholarships/export/")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.streaming)
        self.assertIn("attachment", response["Content-Disposition"])
        body = b"".join(response.streaming_content).decode()
        self.assertEqual(
            body.splitlines()[0], "Name,Host Country,Degree Level,Deadline,Link"
        )
        # Hidden (and expired) rows stay out of the export.
        self.assertNotIn("Inactive", body)
        self.assertIn("Chevening Scholarship", body)

    def test_user_directory_is_paginated_and_never_stored(self):
        Student.objects.create(
            user=User.objects.create_user(
                username="amara", password="Str0ngPassw0rd!", email="amara@example.com"
            ),
            phone="+231 770 000 000",
            country_of_citizenship="Liberia",
            country_of_residence="Ghana",
            education_level="undergraduate",
        )
        cache.clear()

        response = self.client.get("/api/admin/users/")
        self.assertEqual(response.status_code, 200)
        # Personal data must never be kept by a browser or proxy.
        self.assertEqual(response["Cache-Control"], "private, no-store")
        body = response.json()
        self.assertIn("results", body)
        self.assertIn("total_pages", body)
        by_username = {row["username"]: row for row in body["results"]}
        self.assertEqual(by_username["amara"]["user_type"], "Student")
        self.assertEqual(by_username["amara"]["country_of_citizenship"], "Liberia")
        self.assertEqual(by_username["amara"]["education_level"], "Undergraduate")
        self.assertEqual(by_username["boss"]["user_type"], "Super Admin")

        # Search narrows the roster.
        search = self.client.get("/api/admin/users/?q=amara").json()
        self.assertEqual([row["username"] for row in search["results"]], ["amara"])

    def test_user_directory_requires_super_admin(self):
        anon = APIClient()
        self.assertIn(anon.get("/api/admin/users/").status_code, (401, 403))

        # A regular admin manages scholarships, not people: the directory and
        # the users export both stay super-admin-only.
        plain_admin = User.objects.create_user(
            username="plain", password="Str0ngPassw0rd!"
        )
        Admin.objects.create(user=plain_admin, is_super_admin=False)
        cache.clear()
        as_admin = APIClient()
        as_admin.force_authenticate(plain_admin)
        self.assertEqual(as_admin.get("/api/admin/users/").status_code, 403)
        self.assertEqual(as_admin.get("/api/admin/users/export/").status_code, 403)

    def test_users_export_includes_student_profile(self):
        response = self.client.get("/api/admin/users/export/")
        self.assertEqual(response.status_code, 200)
        body = b"".join(response.streaming_content).decode()
        header = body.splitlines()[0]
        for column in (
            "Email",
            "User Type",
            "Phone",
            "Country of Citizenship",
            "Country of Residence",
            "Education Level",
        ):
            self.assertIn(column, header)
        self.assertIn("Super Admin", body)


class ContactTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()

    def test_contact_form_creates_message(self):
        response = self.client.post(
            "/api/contact/",
            {
                "name": "Ada",
                "email": "ada@example.com",
                "message": "I would like help with my application essay.",
            },
            format="json",
        )
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(ContactMessage.objects.count(), 1)

    def test_contact_form_rejects_short_message(self):
        response = self.client.post(
            "/api/contact/",
            {"name": "Ada", "email": "ada@example.com", "message": "hi"},
            format="json",
        )
        self.assertEqual(response.status_code, 400)


class TransactionalEmailTests(TestCase):
    """The React Email templates and the Resend/SMTP delivery service.

    _deliver is exercised synchronously (the public helpers only wrap it in a
    thread) with RESEND_API_KEY unset, so Django's locmem test backend
    captures the message.
    """

    def _last_message(self):
        from django.core import mail

        self.assertEqual(len(mail.outbox), 1)
        return mail.outbox[0]

    def test_welcome_email_renders_html_and_text(self):
        from . import emails

        user = User.objects.create_user(
            "ama", email="ama@example.com", password="x", first_name="Ama"
        )
        with self.settings(RESEND_API_KEY=""):
            emails._deliver(
                to=[user.email],
                subject="Welcome to myScholy",
                template="welcome",
                context={"first_name": user.first_name},
            )
        message = self._last_message()
        self.assertEqual(message.to, ["ama@example.com"])
        self.assertIn("Ama", message.body)  # plain text part
        html, mimetype = message.alternatives[0]
        self.assertEqual(mimetype, "text/html")
        self.assertIn("Ama", html)
        self.assertNotIn("{{", html)

    def test_password_reset_email_contains_link_in_href(self):
        from . import emails

        link = "http://localhost:5173/reset-password?uid=Mg&token=abc-123"
        with self.settings(RESEND_API_KEY=""):
            emails._deliver(
                to=["ama@example.com"],
                subject="Reset your myScholy password",
                template="password-reset",
                context={
                    "first_name": "Ama",
                    "reset_link": link,
                    "expires_in": "1 hour",
                },
            )
        message = self._last_message()
        self.assertIn(link, message.body)
        html = message.alternatives[0][0]
        self.assertIn('href="http://localhost:5173/reset-password?uid=Mg&amp;token=abc-123"', html)

    def test_contact_notification_escapes_html_and_sets_reply_to(self):
        from . import emails

        with self.settings(RESEND_API_KEY=""):
            emails._deliver(
                to=["team@example.com"],
                subject="myScholy contact form: Mallory",
                template="contact-notification",
                context={
                    "name": "Mallory",
                    "email": "mallory@example.com",
                    "received_at": "04 Aug 2026 12:00 UTC",
                    "message": "<script>alert(1)</script>\nsecond line",
                },
                reply_to=["mallory@example.com"],
            )
        message = self._last_message()
        self.assertEqual(message.reply_to, ["mallory@example.com"])
        html = message.alternatives[0][0]
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("second line", html)

    def test_admin_welcome_email_renders_html_and_text(self):
        from . import emails

        with self.settings(RESEND_API_KEY=""):
            emails._deliver(
                to=["kofi@example.com"],
                subject="Welcome to the myScholy admin team",
                template="admin-welcome",
                context={"first_name": "Kofi", "username": "kofi"},
            )
        message = self._last_message()
        self.assertIn("Kofi", message.body)
        self.assertIn("kofi", message.body)
        html = message.alternatives[0][0]
        self.assertIn("Kofi", html)
        self.assertIn("administrator", html)
        self.assertNotIn("{{", html)
        self.assertNotIn("{%", html)

    def test_scholarship_digest_email_lists_every_scholarship(self):
        from . import emails

        rows = [
            make_scholarship(name=f"Digest Award {i}", link=f"https://example.com/{i}")
            for i in range(5)
        ]
        with self.settings(RESEND_API_KEY=""):
            emails.send_scholarship_digest_email(
                to="ama@example.com", first_name="Ama", scholarships=rows
            )
        message = self._last_message()
        html = message.alternatives[0][0]
        for row in rows:
            self.assertIn(row.name, message.body)
            # Links go to our own detail page, never the official site -
            # students should read about the scholarship on the board first.
            detail = f"{settings.FRONTEND_URL}/scholarships/{row.slug}"
            self.assertIn(detail, message.body)
            self.assertNotIn(row.link, message.body)
            self.assertIn(row.name, html)
            self.assertIn(f'href="{detail}"', html)
            self.assertNotIn(f'href="{row.link}"', html)
        # The explore-more redirect back to the site.
        self.assertIn("/scholarships", html)
        self.assertNotIn("{{", html)
        self.assertNotIn("{%", html)


class ScholarshipDigestCommandTests(TestCase):
    """The 15-hourly digest command: 5 random live scholarships to every
    active student, never to admins, archived rows never picked, and never
    twice inside the minimum interval (the DigestRun guard)."""

    def setUp(self):
        cache.clear()

    def _make_student(self, username, email, first_name=""):
        user = User.objects.create_user(
            username, email=email, password="x", first_name=first_name
        )
        Student.objects.create(user=user)
        return user

    def test_digest_goes_to_students_with_live_scholarships_only(self):
        from django.core.management import call_command

        for i in range(7):
            make_scholarship(name=f"Live Award {i}")
        make_scholarship(name="Hidden Award", is_active=False)
        make_scholarship(
            name="Expired Award",
            deadline=timezone.now().date() - timedelta(days=1),
        )

        self._make_student("ama", "ama@example.com", "Ama")
        self._make_student("kofi", "kofi@example.com")
        admin_user = User.objects.create_user(
            "boss", email="boss@example.com", password="x", is_staff=True
        )
        Admin.objects.create(user=admin_user)

        from django.core import mail

        with self.settings(RESEND_API_KEY=""):
            call_command("send_scholarship_digest")

        recipients = sorted(message.to[0] for message in mail.outbox)
        self.assertEqual(recipients, ["ama@example.com", "kofi@example.com"])
        for message in mail.outbox:
            self.assertNotIn("Hidden Award", message.body)
            self.assertNotIn("Expired Award", message.body)
            # 5 picks out of the 7 live rows.
            self.assertEqual(message.body.count("Live Award"), 5)

    def test_dry_run_sends_nothing(self):
        from django.core import mail
        from django.core.management import call_command

        make_scholarship(name="Live Award")
        self._make_student("ama", "ama@example.com", "Ama")
        with self.settings(RESEND_API_KEY=""):
            call_command("send_scholarship_digest", "--dry-run")
        self.assertEqual(mail.outbox, [])
        # Dry runs must not consume the interval guard.
        self.assertEqual(DigestRun.objects.count(), 0)

    def test_full_send_records_a_run(self):
        from django.core import mail
        from django.core.management import call_command

        make_scholarship(name="Live Award")
        self._make_student("ama", "ama@example.com", "Ama")
        with self.settings(RESEND_API_KEY=""):
            call_command("send_scholarship_digest")
        self.assertEqual(len(mail.outbox), 1)
        run = DigestRun.objects.get()
        self.assertEqual(run.recipient_count, 1)

    def test_second_trigger_inside_interval_is_skipped(self):
        from django.core import mail
        from django.core.management import call_command

        make_scholarship(name="Live Award")
        self._make_student("ama", "ama@example.com", "Ama")
        DigestRun.objects.create()  # a digest just went out
        with self.settings(RESEND_API_KEY=""):
            call_command("send_scholarship_digest")
        self.assertEqual(mail.outbox, [])
        self.assertEqual(DigestRun.objects.count(), 1)

    def test_trigger_after_interval_sends_again(self):
        from django.core import mail
        from django.core.management import call_command

        from .management.commands.send_scholarship_digest import (
            MIN_HOURS_BETWEEN_RUNS,
        )

        make_scholarship(name="Live Award")
        self._make_student("ama", "ama@example.com", "Ama")
        stale = DigestRun.objects.create()
        DigestRun.objects.filter(pk=stale.pk).update(
            sent_at=timezone.now() - timedelta(hours=MIN_HOURS_BETWEEN_RUNS, minutes=5)
        )
        with self.settings(RESEND_API_KEY=""):
            call_command("send_scholarship_digest")
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(DigestRun.objects.count(), 2)

    def test_to_flag_bypasses_the_guard_for_testing(self):
        from django.core import mail
        from django.core.management import call_command

        make_scholarship(name="Live Award")
        DigestRun.objects.create()  # would block a full send
        with self.settings(RESEND_API_KEY=""):
            call_command("send_scholarship_digest", "--to", "me@example.com")
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ["me@example.com"])
        # Test sends never count as the scheduled digest.
        self.assertEqual(DigestRun.objects.count(), 1)


class RegistrationValidationTests(TestCase):
    """The API must reject bad input on its own - the React form's checks are
    a convenience, and anything at all can POST here."""

    def setUp(self):
        cache.clear()
        self.client = APIClient()

    def register(self, **overrides):
        payload = {
            "user": {
                "username": "ama@example.com",
                "email": "ama@example.com",
                "first_name": "Ama",
                "last_name": "Boateng",
                "password": "An0therStr0ng!",
            },
            "phone": "+233 20 123 4567",
            "country_of_citizenship": "Ghana",
            "country_of_residence": "Ghana",
            "education_level": "graduate",
        }
        user_overrides = overrides.pop("user", None)
        if user_overrides is not None:
            payload["user"].update(user_overrides)
        payload.update(overrides)
        return self.client.post("/api/auth/student/register/", payload, format="json")

    def assert_rejects(self, response, field, fragment):
        self.assertEqual(response.status_code, 400, response.content)
        body = response.json()
        self.assertIn(field, body)
        value = body[field]
        message = " ".join(value if isinstance(value, list) else [str(value)])
        self.assertIn(fragment, message.lower())

    def test_valid_payload_is_accepted(self):
        self.assertEqual(self.register().status_code, 201)

    def test_password_is_stored_hashed(self):
        """Guards UserSerializer.create(): ModelSerializer's default create()
        writes the raw string straight into the password column."""
        self.assertEqual(self.register().status_code, 201)
        user = User.objects.get(email="ama@example.com")
        self.assertNotEqual(user.password, "An0therStr0ng!")
        # "<algorithm>$<iterations>$<salt>$<hash>" - the algorithm varies
        # (these tests use MD5 for speed), an unhashed value has no $ at all.
        self.assertIn("$", user.password)
        self.assertTrue(user.check_password("An0therStr0ng!"))

    def test_citizenship_is_required(self):
        self.assert_rejects(
            self.register(country_of_citizenship=""),
            "country_of_citizenship",
            "citizenship",
        )

    def test_residence_is_required(self):
        self.assert_rejects(
            self.register(country_of_residence=""),
            "country_of_residence",
            "residence",
        )

    def test_education_level_is_required(self):
        self.assert_rejects(
            self.register(education_level=""), "education_level", "education level"
        )

    def test_education_level_rejects_unknown_value(self):
        self.assert_rejects(
            self.register(education_level="phd"), "education_level", "high school"
        )

    def test_education_level_accepts_each_choice(self):
        for index, level in enumerate(["high_school", "undergraduate", "graduate"]):
            email = "student{}@example.com".format(index)
            response = self.register(
                user={"username": email, "email": email}, education_level=level
            )
            self.assertEqual(response.status_code, 201, response.content)
            self.assertEqual(
                Student.objects.get(user__email=email).education_level, level
            )

    def test_malformed_phone_is_rejected(self):
        self.assert_rejects(self.register(phone="not-a-number"), "phone", "+231")

    def test_blank_phone_is_allowed(self):
        self.assertEqual(self.register(phone="").status_code, 201)

    def test_invalid_email_is_rejected(self):
        response = self.register(user={"email": "ama@@example"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("email", response.json()["user"])

    def test_duplicate_email_is_rejected_with_guidance(self):
        self.assertEqual(self.register().status_code, 201)
        response = self.register()
        self.assertEqual(response.status_code, 400)
        message = " ".join(response.json()["user"]["email"])
        self.assertIn("already exists", message)

    def test_short_password_is_rejected(self):
        response = self.register(user={"password": "short1"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("8 characters", " ".join(response.json()["user"]["password"]))

    def test_all_numeric_password_is_rejected(self):
        response = self.register(user={"password": "9184756231"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("password", response.json()["user"])

    def test_name_with_digits_is_rejected(self):
        response = self.register(user={"first_name": "Ama123"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("first_name", response.json()["user"])

    def test_missing_names_are_rejected(self):
        response = self.register(user={"first_name": "", "last_name": ""})
        self.assertEqual(response.status_code, 400)
        body = response.json()["user"]
        self.assertIn("first_name", body)
        self.assertIn("last_name", body)


class ContactValidationTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()

    def post(self, **overrides):
        payload = {
            "name": "Ada",
            "email": "ada@example.com",
            "message": "I would like help with my application essay.",
        }
        payload.update(overrides)
        return self.client.post("/api/contact/", payload, format="json")

    def test_invalid_email_is_rejected(self):
        response = self.post(email="ada@@example")
        self.assertEqual(response.status_code, 400)
        self.assertIn("email", response.json())

    def test_name_with_digits_is_rejected(self):
        response = self.post(name="Ada99")
        self.assertEqual(response.status_code, 400)
        self.assertIn("name", response.json())

    def test_overlong_message_is_rejected(self):
        response = self.post(message="x" * 5001)
        self.assertEqual(response.status_code, 400)
        self.assertIn("5000", " ".join(response.json()["message"]))

    def test_email_is_normalised_to_lowercase(self):
        self.assertEqual(self.post(email="Ada@Example.COM").status_code, 201)
        self.assertEqual(ContactMessage.objects.get().email, "ada@example.com")


class ScholarshipValidationTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.admin_user = User.objects.create_user(
            username="editor", password="Str0ngPassw0rd!", is_staff=True
        )
        Admin.objects.create(user=self.admin_user, is_super_admin=True)
        self.client.force_authenticate(self.admin_user)

    def post(self, **overrides):
        payload = {
            "name": "Chevening Scholarship",
            "description": "Fully funded postgraduate study in the United Kingdom.",
            "deadline": (timezone.now().date() + timedelta(days=30)).isoformat(),
            "host_country": "United Kingdom",
            "benefits": "Tuition\nStipend",
            "eligibility": "An undergraduate degree",
            "degree_level": "Masters",
            "link": "https://example.com/apply",
            "author": "myScholy",
        }
        payload.update(overrides)
        return self.client.post("/api/scholarships/", payload, format="json")

    def test_valid_payload_is_accepted(self):
        response = self.post()
        self.assertEqual(response.status_code, 201, response.content)

    def test_link_must_be_a_full_url(self):
        response = self.post(link="example.com/apply")
        self.assertEqual(response.status_code, 400)
        self.assertIn("link", response.json())

    def test_past_deadline_is_rejected_on_create(self):
        response = self.post(
            deadline=(timezone.now().date() - timedelta(days=1)).isoformat()
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("already passed", " ".join(response.json()["deadline"]))

    def test_thin_description_is_rejected(self):
        response = self.post(description="Short.")
        self.assertEqual(response.status_code, 400)
        self.assertIn("description", response.json())


class AssistantTests(TestCase):
    """The Gemini-backed popup assistant endpoints."""

    def setUp(self):
        cache.clear()
        self.client = APIClient()

    def test_status_reports_disabled_without_key(self):
        with self.settings(GEMINI_API_KEY=""):
            response = self.client.get("/api/assistant/")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.data["enabled"])

    def test_status_reports_enabled_with_key(self):
        with self.settings(GEMINI_API_KEY="test-key"):
            response = self.client.get("/api/assistant/")
        self.assertTrue(response.data["enabled"])

    def test_chat_disabled_without_key(self):
        with self.settings(GEMINI_API_KEY=""):
            response = self.client.post(
                "/api/assistant/chat/", {"message": "hello"}, format="json"
            )
        self.assertEqual(response.status_code, 503)

    def test_chat_rejects_empty_message(self):
        with self.settings(GEMINI_API_KEY="test-key"):
            response = self.client.post(
                "/api/assistant/chat/", {"message": "   "}, format="json"
            )
        self.assertEqual(response.status_code, 400)

    def test_chat_relays_reply_and_never_caches(self):
        from unittest.mock import patch

        with self.settings(GEMINI_API_KEY="test-key"):
            with patch(
                "scholarships.assistant.ask", return_value="Try the Chevening listing."
            ) as mock_ask:
                response = self.client.post(
                    "/api/assistant/chat/",
                    {
                        "message": "Any UK scholarships?",
                        "history": [
                            {"role": "user", "text": "hi"},
                            {"role": "model", "text": "hello"},
                            {"role": "bogus", "text": "dropped"},
                        ],
                    },
                    format="json",
                )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["reply"], "Try the Chevening listing.")
        self.assertEqual(response["Cache-Control"], "private, no-store")
        # Malformed history entries are dropped before reaching the provider.
        self.assertEqual(
            mock_ask.call_args[0][1],
            [{"role": "user", "text": "hi"}, {"role": "model", "text": "hello"}],
        )

    def test_chat_translates_provider_failure(self):
        from unittest.mock import patch

        from .assistant import AssistantError

        with self.settings(GEMINI_API_KEY="test-key"):
            with patch(
                "scholarships.assistant.ask",
                side_effect=AssistantError("The assistant is taking a break."),
            ):
                response = self.client.post(
                    "/api/assistant/chat/", {"message": "hello"}, format="json"
                )
        self.assertEqual(response.status_code, 503)
        self.assertIn("break", response.data["error"])

    def test_context_uses_only_live_matching_rows(self):
        from .assistant import _context_scholarships

        make_scholarship(name="Tokyo Tech Award", host_country="Japan")
        make_scholarship(
            name="Closed Japan Award",
            host_country="Japan",
            deadline=timezone.now().date() - timedelta(days=1),
        )
        context = _context_scholarships("scholarships in Japan please")
        self.assertIn("Tokyo Tech Award", context)
        self.assertNotIn("Closed Japan Award", context)


class AssistantExtractTests(TestCase):
    """The admin paste-and-auto-fill extraction endpoint."""

    URL = "/api/admin/assistant/extract-scholarship/"
    SAMPLE = (
        "The Example Fellowship 2027 offers fully funded masters study in "
        "Germany. Deadline: 1 March 2027. Apply at https://example.org/apply."
    )

    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.admin_user = User.objects.create_user("staff", password="x")
        Admin.objects.create(user=self.admin_user)

    def test_requires_admin(self):
        with self.settings(GEMINI_API_KEY="test-key"):
            response = self.client.post(self.URL, {"text": self.SAMPLE}, format="json")
        self.assertIn(response.status_code, (401, 403))

    def test_rejects_short_text(self):
        self.client.force_authenticate(self.admin_user)
        with self.settings(GEMINI_API_KEY="test-key"):
            response = self.client.post(self.URL, {"text": "too short"}, format="json")
        self.assertEqual(response.status_code, 400)

    def test_disabled_without_key(self):
        self.client.force_authenticate(self.admin_user)
        with self.settings(GEMINI_API_KEY=""):
            response = self.client.post(self.URL, {"text": self.SAMPLE}, format="json")
        self.assertEqual(response.status_code, 503)

    def test_returns_extracted_fields(self):
        from unittest.mock import patch

        extracted = {
            "name": "Example Fellowship 2027",
            "description": "Fully funded masters study in Germany.",
            "deadline": "2027-03-01",
            "host_country": "Germany",
            "degree_level": "Masters",
            "benefits": "Tuition\nStipend",
            "eligibility": "",
            "link": "https://example.org/apply",
        }
        self.client.force_authenticate(self.admin_user)
        with self.settings(GEMINI_API_KEY="test-key"):
            with patch(
                "scholarships.assistant.extract_scholarship", return_value=extracted
            ) as mock_extract:
                response = self.client.post(
                    self.URL, {"text": self.SAMPLE}, format="json"
                )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["fields"], extracted)
        self.assertEqual(response["Cache-Control"], "private, no-store")
        mock_extract.assert_called_once()

    def test_extract_parses_model_json(self):
        from unittest.mock import patch

        from .assistant import extract_scholarship

        model_reply = (
            '{"name": "Example Fellowship", "description": "d", "deadline": "",'
            ' "host_country": "Germany", "degree_level": "Masters",'
            ' "benefits": "Tuition", "eligibility": "", "link": ""}'
        )
        with patch("scholarships.assistant._generate", return_value=model_reply):
            fields = extract_scholarship("some pasted announcement")
        self.assertEqual(fields["name"], "Example Fellowship")
        self.assertEqual(fields["deadline"], "")
        self.assertEqual(fields["host_country"], "Germany")


class AssistantExtractSourceTests(TestCase):
    """URL and PDF sources for the admin extraction endpoint."""

    URL = "/api/admin/assistant/extract-scholarship/"

    def setUp(self):
        cache.clear()
        self.client = APIClient()
        admin_user = User.objects.create_user("staff2", password="x")
        Admin.objects.create(user=admin_user)
        self.client.force_authenticate(admin_user)

    def test_url_must_be_public_http(self):
        with self.settings(GEMINI_API_KEY="test-key"):
            response = self.client.post(
                self.URL, {"url": "http://127.0.0.1/internal"}, format="json"
            )
        self.assertEqual(response.status_code, 400)

    def test_url_fetch_feeds_extraction(self):
        from unittest.mock import patch

        with self.settings(GEMINI_API_KEY="test-key"):
            with patch(
                "scholarships.assistant.fetch_url",
                return_value=("text", "A long announcement about a fully funded award " * 3),
            ):
                with patch(
                    "scholarships.assistant.extract_scholarship",
                    return_value={"name": "From URL"},
                ) as mock_extract:
                    response = self.client.post(
                        self.URL, {"url": "https://example.org/award"}, format="json"
                    )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["fields"]["name"], "From URL")
        self.assertIn("text", mock_extract.call_args.kwargs)

    def test_pdf_upload_feeds_extraction(self):
        from unittest.mock import patch

        from django.core.files.uploadedfile import SimpleUploadedFile

        pdf = SimpleUploadedFile(
            "award.pdf", b"%PDF-1.4 fake body", content_type="application/pdf"
        )
        with self.settings(GEMINI_API_KEY="test-key"):
            with patch(
                "scholarships.assistant.extract_scholarship",
                return_value={"name": "From PDF"},
            ) as mock_extract:
                response = self.client.post(self.URL, {"pdf": pdf}, format="multipart")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["fields"]["name"], "From PDF")
        self.assertIn("pdf_bytes", mock_extract.call_args.kwargs)

    def test_non_pdf_upload_rejected(self):
        from django.core.files.uploadedfile import SimpleUploadedFile

        fake = SimpleUploadedFile("award.pdf", b"just text", content_type="application/pdf")
        with self.settings(GEMINI_API_KEY="test-key"):
            response = self.client.post(self.URL, {"pdf": fake}, format="multipart")
        self.assertEqual(response.status_code, 400)

    def test_html_to_text_strips_markup(self):
        from .assistant import _html_to_text

        text = _html_to_text(
            "<html><head><style>p{color:red}</style></head>"
            "<body><h1>Award</h1><p>Fully &amp; truly funded.</p>"
            "<script>alert(1)</script></body></html>"
        )
        self.assertIn("Award", text)
        self.assertIn("Fully & truly funded.", text)
        self.assertNotIn("alert", text)
        self.assertNotIn("color", text)


class AssistantDuplicateTests(TestCase):
    """Advisory duplicate detection for extracted scholarships."""

    def setUp(self):
        cache.clear()

    def test_no_candidates_skips_the_model_entirely(self):
        from unittest.mock import patch

        from .assistant import find_possible_duplicate

        with patch("scholarships.assistant._generate") as mock_generate:
            result = find_possible_duplicate({"name": "Totally Unseen Award"})
        self.assertIsNone(result)
        mock_generate.assert_not_called()

    def test_reports_archived_match(self):
        from unittest.mock import patch

        from .assistant import find_possible_duplicate

        row = make_scholarship(
            name="Yenching Academy Scholarship 2025",
            deadline=timezone.now().date() - timedelta(days=100),
        )
        with patch(
            "scholarships.assistant._generate",
            return_value=f'{{"match_id": {row.pk}}}',
        ):
            result = find_possible_duplicate(
                {"name": "Yenching Academy Scholarship 2026", "host_country": "China"}
            )
        self.assertEqual(result, {"name": row.name, "status": "archived"})

    def test_reports_live_match(self):
        from unittest.mock import patch

        from .assistant import find_possible_duplicate

        row = make_scholarship(name="Yenching Academy Scholarship")
        with patch(
            "scholarships.assistant._generate",
            return_value=f'{{"match_id": {row.pk}}}',
        ):
            result = find_possible_duplicate({"name": "Yenching Academy Scholarship"})
        self.assertEqual(result, {"name": row.name, "status": "live"})

    def test_model_failure_returns_none(self):
        from unittest.mock import patch

        from .assistant import AssistantError, find_possible_duplicate

        make_scholarship(name="Yenching Academy Scholarship")
        with patch(
            "scholarships.assistant._generate",
            side_effect=AssistantError("down"),
        ):
            result = find_possible_duplicate({"name": "Yenching Academy Scholarship"})
        self.assertIsNone(result)

    def test_extraction_response_carries_duplicate(self):
        from unittest.mock import patch

        client = APIClient()
        admin_user = User.objects.create_user("staff3", password="x")
        Admin.objects.create(user=admin_user)
        client.force_authenticate(admin_user)

        with self.settings(GEMINI_API_KEY="test-key"):
            with patch(
                "scholarships.assistant.extract_scholarship",
                return_value={"name": "Some Award"},
            ):
                with patch(
                    "scholarships.assistant.find_possible_duplicate",
                    return_value={"name": "Some Award 2025", "status": "archived"},
                ):
                    response = client.post(
                        "/api/admin/assistant/extract-scholarship/",
                        {"text": "A long enough announcement about the Some Award programme."},
                        format="json",
                    )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data["duplicate"],
            {"name": "Some Award 2025", "status": "archived"},
        )


class CreateDuplicateGuardTests(TestCase):
    """The post-time duplicate safety net on admin create."""

    URL = "/api/admin/scholarships/"

    def setUp(self):
        cache.clear()
        self.client = APIClient()
        admin_user = User.objects.create_user("poster", password="x")
        Admin.objects.create(user=admin_user)
        self.client.force_authenticate(admin_user)
        self.payload = {
            "name": "Yenching Academy Scholarship 2027",
            "description": "Fully funded graduate study at Peking University.",
            "deadline": str(timezone.now().date() + timedelta(days=60)),
            "host_country": "China",
            "benefits": "Tuition\nStipend",
            "eligibility": "Bachelor's degree",
            "degree_level": "Masters",
            "link": "https://example.com/apply",
            "author": "myScholy",
            "is_active": True,
        }

    def test_create_warns_then_posts_on_confirm(self):
        from unittest.mock import patch

        duplicate = {"name": "Yenching Academy Scholarship 2026", "status": "archived"}
        with self.settings(GEMINI_API_KEY="test-key"):
            with patch(
                "scholarships.assistant.find_possible_duplicate",
                return_value=duplicate,
            ) as mock_check:
                first = self.client.post(self.URL, self.payload, format="json")
                self.assertEqual(first.status_code, 409)
                self.assertEqual(first.data["duplicate"], duplicate)
                self.assertEqual(Scholarship.objects.count(), 0)

                second = self.client.post(
                    self.URL,
                    {**self.payload, "confirm_duplicate": True},
                    format="json",
                )
                self.assertEqual(second.status_code, 201)
                self.assertEqual(Scholarship.objects.count(), 1)
                # The confirmed resubmit must not pay for a second AI call.
                mock_check.assert_called_once()

    def test_create_skips_check_without_key(self):
        from unittest.mock import patch

        with self.settings(GEMINI_API_KEY=""):
            with patch(
                "scholarships.assistant.find_possible_duplicate"
            ) as mock_check:
                response = self.client.post(self.URL, self.payload, format="json")
        self.assertEqual(response.status_code, 201)
        mock_check.assert_not_called()

    def test_create_proceeds_when_no_duplicate_found(self):
        from unittest.mock import patch

        with self.settings(GEMINI_API_KEY="test-key"):
            with patch(
                "scholarships.assistant.find_possible_duplicate", return_value=None
            ):
                response = self.client.post(self.URL, self.payload, format="json")
        self.assertEqual(response.status_code, 201)


class AssistantAssessmentTests(TestCase):
    """The personalized assessment endpoint."""

    URL = "/api/assistant/assessment/"
    ANSWERS = {
        "age": "18plus",
        "level": "graduate",
        "stage": "exploring",
        "essay": "draft",
        "cv": "yes",
        "region": "Asia",
    }

    def setUp(self):
        cache.clear()
        self.client = APIClient()

    def test_disabled_without_key(self):
        with self.settings(GEMINI_API_KEY=""):
            response = self.client.post(
                self.URL, {"answers": self.ANSWERS}, format="json"
            )
        self.assertEqual(response.status_code, 503)

    def test_rejects_missing_answers(self):
        with self.settings(GEMINI_API_KEY="test-key"):
            response = self.client.post(self.URL, {"answers": {}}, format="json")
        self.assertEqual(response.status_code, 400)

    def test_returns_personalized_result(self):
        from unittest.mock import patch

        payload = {
            "headline": "You're closer than you think",
            "summary": "A personalized paragraph.",
            "next_steps": ["Do one thing", "Then another"],
            "scholarships": [
                {
                    "id": 1,
                    "name": "Yenching",
                    "host_country": "China",
                    "degree_level": "Masters",
                    "deadline": "16 Sep 2026",
                }
            ],
        }
        with self.settings(GEMINI_API_KEY="test-key"):
            with patch(
                "scholarships.assistant.personalized_assessment", return_value=payload
            ) as mock_assess:
                response = self.client.post(
                    self.URL, {"answers": self.ANSWERS}, format="json"
                )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, payload)
        self.assertEqual(response["Cache-Control"], "private, no-store")
        mock_assess.assert_called_once()

    def test_personalized_assessment_resolves_real_rows(self):
        from unittest.mock import patch

        row = make_scholarship(name="Asia Masters Award", degree_level="Masters")
        model_reply = (
            '{"headline": "h", "summary": "s", "next_steps": ["a"],'
            f' "scholarship_ids": [{row.pk}, 999999]}}'
        )
        from .assistant import personalized_assessment

        with patch("scholarships.assistant._generate", return_value=model_reply):
            result = personalized_assessment({"level": "graduate", "region": "Asia"})
        self.assertEqual(len(result["scholarships"]), 1)
        self.assertEqual(result["scholarships"][0]["name"], "Asia Masters Award")
        self.assertEqual(result["scholarships"][0]["id"], row.pk)


class AiQuotaThrottleTests(TestCase):
    """The 20-hour rolling quotas on the AI endpoints."""

    def setUp(self):
        cache.clear()
        self.client = APIClient()

    def _post_assessment(self, client):
        from unittest.mock import patch

        payload = {
            "headline": "h",
            "summary": "s",
            "next_steps": [],
            "scholarships": [],
        }
        with self.settings(GEMINI_API_KEY="test-key"):
            with patch(
                "scholarships.assistant.personalized_assessment", return_value=payload
            ):
                return client.post(
                    "/api/assistant/assessment/",
                    {"answers": {"level": "graduate"}},
                    format="json",
                )

    def test_anonymous_assessment_limited_to_one(self):
        first = self._post_assessment(self.client)
        self.assertEqual(first.status_code, 200)

        second = self._post_assessment(self.client)
        self.assertEqual(second.status_code, 429)
        # Guests get the log-in invitation, not the reset countdown.
        self.assertIn("log in", second.data["error"])
        self.assertNotIn("check back", second.data["error"])
        self.assertTrue(second.data["requires_login"])
        self.assertIn("retry_after_seconds", second.data)
        self.assertTrue(second.has_header("Retry-After"))

    def test_logged_in_assessment_gets_five(self):
        user = User.objects.create_user("quota-user", password="x")
        self.client.force_authenticate(user)

        for _ in range(5):
            self.assertEqual(self._post_assessment(self.client).status_code, 200)

        sixth = self._post_assessment(self.client)
        self.assertEqual(sixth.status_code, 429)
        # Logged-in users get the reset countdown, not a log-in invitation.
        self.assertIn("check back", sixth.data["error"])
        self.assertNotIn("log in", sixth.data["error"])
        self.assertFalse(sixth.data["requires_login"])

    def _post_chat(self, client):
        from unittest.mock import patch

        with self.settings(GEMINI_API_KEY="test-key"):
            with patch("scholarships.assistant.ask", return_value="reply"):
                return client.post(
                    "/api/assistant/chat/", {"message": "hello"}, format="json"
                )

    def test_anonymous_chat_limited_to_three(self):
        for _ in range(3):
            self.assertEqual(self._post_chat(self.client).status_code, 200)
        fourth = self._post_chat(self.client)
        self.assertEqual(fourth.status_code, 429)
        self.assertIn("log in", fourth.data["error"])
        self.assertTrue(fourth.data["requires_login"])

    def test_logged_in_chat_gets_ten(self):
        user = User.objects.create_user("chat-user", password="x")
        self.client.force_authenticate(user)
        for _ in range(10):
            self.assertEqual(self._post_chat(self.client).status_code, 200)
        eleventh = self._post_chat(self.client)
        self.assertEqual(eleventh.status_code, 429)

    def test_quota_window_is_twenty_hours(self):
        from .throttling import AssessmentQuotaThrottle, ChatQuotaThrottle

        self.assertEqual(AssessmentQuotaThrottle().duration, 20 * 3600)
        self.assertEqual(ChatQuotaThrottle().duration, 20 * 3600)


class AiResponseCacheTests(TestCase):
    """Identical AI inputs must never reach the provider twice."""

    def setUp(self):
        cache.clear()

    def test_identical_chat_reuses_reply(self):
        from unittest.mock import patch

        from .assistant import ask

        with patch(
            "scholarships.assistant._generate", return_value="You can apply via the board."
        ) as mock_generate:
            first = ask("How do I apply?", [])
            second = ask("How do I apply?", [])
        self.assertEqual(first, second)
        mock_generate.assert_called_once()

    def test_chat_cache_ignores_letter_case(self):
        from unittest.mock import patch

        from .assistant import ask

        with patch(
            "scholarships.assistant._generate", return_value="reply"
        ) as mock_generate:
            ask("How do I apply?", [])
            ask("HOW DO I APPLY?  ", [])
        mock_generate.assert_called_once()

    def test_board_change_invalidates_chat_cache(self):
        from unittest.mock import patch

        from .assistant import ask

        with patch(
            "scholarships.assistant._generate", return_value="reply"
        ) as mock_generate:
            ask("Any new scholarships?", [])
            make_scholarship(name="Fresh Award")  # bumps the cache version
            ask("Any new scholarships?", [])
        self.assertEqual(mock_generate.call_count, 2)

    def test_identical_assessment_reuses_plan(self):
        from unittest.mock import patch

        from .assistant import personalized_assessment

        reply = '{"headline": "h", "summary": "s", "next_steps": [], "scholarship_ids": []}'
        answers = {"level": "graduate", "region": "Asia"}
        with patch(
            "scholarships.assistant._generate", return_value=reply
        ) as mock_generate:
            first = personalized_assessment(answers)
            second = personalized_assessment(dict(answers))
        self.assertEqual(first, second)
        mock_generate.assert_called_once()

    def test_identical_extraction_reuses_fields(self):
        from unittest.mock import patch

        from .assistant import extract_scholarship

        reply = (
            '{"name": "A", "description": "", "deadline": "", "host_country": "",'
            ' "degree_level": "", "benefits": "", "eligibility": "", "link": ""}'
        )
        with patch(
            "scholarships.assistant._generate", return_value=reply
        ) as mock_generate:
            extract_scholarship(text="The same announcement text pasted twice.")
            extract_scholarship(text="The same announcement text pasted twice.")
        mock_generate.assert_called_once()

    def test_failures_are_not_cached(self):
        from unittest.mock import patch

        from .assistant import AssistantError, ask

        with patch(
            "scholarships.assistant._generate",
            side_effect=[AssistantError("down"), "recovered"],
        ) as mock_generate:
            with self.assertRaises(AssistantError):
                ask("Hello?", [])
            self.assertEqual(ask("Hello?", []), "recovered")
        self.assertEqual(mock_generate.call_count, 2)


class ProviderFailoverTests(TestCase):
    """Gemini <-> Groq automatic failover in assistant._generate."""

    def setUp(self):
        cache.clear()

    def _generate(self):
        from .assistant import _generate

        return _generate(
            "system", [{"role": "user", "text": "hi"}], temperature=0, max_tokens=50
        )

    def test_gemini_rate_limit_fails_over_to_groq(self):
        from unittest.mock import patch

        from .assistant import ProviderError

        with self.settings(GEMINI_API_KEY="g-key", GROQ_API_KEY="q-key"):
            with patch(
                "scholarships.assistant._gemini_call",
                side_effect=ProviderError("429", rate_limited=True),
            ) as gemini:
                with patch(
                    "scholarships.assistant._groq_call", return_value="from groq"
                ) as groq:
                    self.assertEqual(self._generate(), "from groq")
                    # Gemini is now cooling down: the next request goes
                    # straight to Groq without touching Gemini again.
                    self.assertEqual(self._generate(), "from groq")
            self.assertEqual(gemini.call_count, 1)
            self.assertEqual(groq.call_count, 2)

    def test_both_rate_limited_reports_busy(self):
        from unittest.mock import patch

        from .assistant import AssistantError, ProviderError

        with self.settings(GEMINI_API_KEY="g-key", GROQ_API_KEY="q-key"):
            with patch(
                "scholarships.assistant._gemini_call",
                side_effect=ProviderError("429", rate_limited=True),
            ):
                with patch(
                    "scholarships.assistant._groq_call",
                    side_effect=ProviderError("429", rate_limited=True),
                ):
                    with self.assertRaises(AssistantError) as caught:
                        self._generate()
        self.assertIn("Too many users", str(caught.exception))
        self.assertIn("try again in a minute", str(caught.exception))

    def test_gemini_transient_error_also_fails_over(self):
        from unittest.mock import patch

        from .assistant import ProviderError

        with self.settings(GEMINI_API_KEY="g-key", GROQ_API_KEY="q-key"):
            with patch(
                "scholarships.assistant._gemini_call",
                side_effect=ProviderError("unreachable"),
            ):
                with patch(
                    "scholarships.assistant._groq_call", return_value="from groq"
                ):
                    self.assertEqual(self._generate(), "from groq")

    def test_no_groq_key_keeps_gemini_only_behaviour(self):
        from unittest.mock import patch

        from .assistant import AssistantError, ProviderError

        with self.settings(GEMINI_API_KEY="g-key", GROQ_API_KEY=""):
            with patch(
                "scholarships.assistant._gemini_call",
                side_effect=ProviderError("429", rate_limited=True),
            ):
                with patch("scholarships.assistant._groq_call") as groq:
                    with self.assertRaises(AssistantError):
                        self._generate()
                    groq.assert_not_called()

    def test_pdf_requests_never_reach_groq(self):
        from .assistant import ProviderError, _groq_call

        with self.assertRaises(ProviderError) as caught:
            _groq_call(
                "system",
                [{"role": "user", "pdf": b"%PDF-", "text": "extract"}],
                0,
                100,
                None,
            )
        self.assertTrue(caught.exception.unsupported)


class SecureDefaultsTests(TestCase):
    """Settings must be safe on a host that sets no environment variables."""

    def _reload_settings_with_env(self, env):
        """Re-import the settings module against a controlled environment.

        ``load_dotenv`` is stubbed out because settings.py loads .env with
        override=True - without this the developer's own .env would decide the
        outcome and the assertion would prove nothing on another machine.
        Reloading mutates only the module object; django.conf.settings holds a
        separate copy, so the running suite is unaffected.
        """
        import importlib

        from scholarship_backend import settings as settings_module

        with mock.patch("dotenv.load_dotenv", return_value=False):
            with mock.patch.dict(os.environ, env, clear=True):
                return importlib.reload(settings_module)

    def tearDown(self):
        # Restore the module to the real environment for any later test.
        self._reload_settings_with_env(dict(os.environ))

    def test_debug_defaults_to_false(self):
        """Debug is opt-in. A deployment that forgets DJANGO_DEBUG must not
        serve Django's technical error pages to the public."""
        self.assertFalse(self._reload_settings_with_env({}).DEBUG)

    def test_debug_can_be_opted_into(self):
        self.assertTrue(
            self._reload_settings_with_env({"DJANGO_DEBUG": "True"}).DEBUG
        )

    def test_environment_beats_the_dotenv_file(self):
        """A deployed host must be able to correct a setting from its own
        environment. With override=True the .env file won instead, so a
        server whose file said DJANGO_DEBUG=True stayed in debug no matter
        what its platform configuration said."""
        import importlib

        from scholarship_backend import settings as settings_module

        with mock.patch("dotenv.load_dotenv", return_value=True) as loader:
            with mock.patch.dict(os.environ, {}, clear=True):
                importlib.reload(settings_module)

        self.assertTrue(loader.call_args_list, "settings.py must load .env")
        for call in loader.call_args_list:
            self.assertFalse(
                call.kwargs.get("override", False),
                "load_dotenv must not override real environment variables",
            )

    def test_production_hardening_follows_debug(self):
        """With debug off the security block must engage on its own."""
        settings_module = self._reload_settings_with_env({})
        self.assertTrue(settings_module.SESSION_COOKIE_SECURE)
        self.assertTrue(settings_module.CSRF_COOKIE_SECURE)
        self.assertTrue(settings_module.SECURE_CONTENT_TYPE_NOSNIFF)
        self.assertEqual(settings_module.X_FRAME_OPTIONS, "DENY")


class AdminMessagesTests(TestCase):
    """The super-admin messages screen: reply to contact messages, compose
    new mail, and the sent history. Everything sends from DEFAULT_FROM_EMAIL
    (the myScholy address) - never from a personal account."""

    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.super_admin = User.objects.create_user(
            username="root", password="Str0ngPassw0rd!", is_staff=True
        )
        Admin.objects.create(user=self.super_admin, is_super_admin=True)
        self.plain_admin = User.objects.create_user(
            username="editor", password="Str0ngPassw0rd!", is_staff=True
        )
        Admin.objects.create(user=self.plain_admin, is_super_admin=False)
        self.message = ContactMessage.objects.create(
            name="Ama", email="ama@example.com", message="How do I apply for DAAD?"
        )

    def _outbox(self):
        from django.core import mail

        return mail.outbox

    def test_reply_sends_marks_handled_and_records(self):
        self.client.force_authenticate(self.super_admin)
        with self.settings(RESEND_API_KEY=""):
            response = self.client.post(
                f"/api/admin/contact/{self.message.pk}/reply/",
                {"body": "Hi Ama, start at the DAAD page on our board."},
                format="json",
            )
        self.assertEqual(response.status_code, 201)
        sent = self._outbox()[-1]
        self.assertEqual(sent.to, ["ama@example.com"])
        self.assertEqual(sent.from_email, settings.DEFAULT_FROM_EMAIL)
        self.assertIn("DAAD", sent.body)
        self.message.refresh_from_db()
        self.assertTrue(self.message.is_handled)
        record = OutboundMessage.objects.get()
        self.assertEqual(record.contact_message, self.message)
        self.assertEqual(record.sent_by, self.super_admin)

    def test_reply_requires_super_admin(self):
        self.client.force_authenticate(self.plain_admin)
        response = self.client.post(
            f"/api/admin/contact/{self.message.pk}/reply/",
            {"body": "should not send"},
            format="json",
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(OutboundMessage.objects.count(), 0)

    def test_compose_sends_and_appears_in_history(self):
        self.client.force_authenticate(self.super_admin)
        with self.settings(RESEND_API_KEY=""):
            response = self.client.post(
                "/api/admin/messages/",
                {
                    "to_email": "partner@example.com",
                    "subject": "Partnership",
                    "body": "Hello from the myScholy team.",
                },
                format="json",
            )
        self.assertEqual(response.status_code, 201)
        history = self.client.get("/api/admin/messages/").json()
        self.assertEqual(history["count"], 1)
        row = history["results"][0]
        self.assertEqual(row["to_email"], "partner@example.com")
        self.assertIsNone(row["contact_message"])
        self.assertEqual(row["sent_by"], "root")

    def test_compose_validates_input(self):
        self.client.force_authenticate(self.super_admin)
        response = self.client.post(
            "/api/admin/messages/",
            {"to_email": "not-an-email", "subject": "", "body": ""},
            format="json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(len(self._outbox()), 0)

    def test_inbox_includes_replies_and_handled_flag(self):
        self.client.force_authenticate(self.super_admin)
        with self.settings(RESEND_API_KEY=""):
            self.client.post(
                f"/api/admin/contact/{self.message.pk}/reply/",
                {"body": "Answered."},
                format="json",
            )
        inbox = self.client.get("/api/admin/contact/").json()
        row = inbox["results"][0]
        self.assertTrue(row["is_handled"])
        self.assertEqual(len(row["replies"]), 1)
        self.assertEqual(
            self.client.get("/api/admin/contact/?status=open").json()["count"], 0
        )

    def test_toggle_handled(self):
        self.client.force_authenticate(self.super_admin)
        response = self.client.patch(
            f"/api/admin/contact/{self.message.pk}/",
            {"is_handled": True},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        self.message.refresh_from_db()
        self.assertTrue(self.message.is_handled)
