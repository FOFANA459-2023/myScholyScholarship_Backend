from datetime import timedelta

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from .models import Admin, ContactMessage, Scholarship, Student


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
        "author": "MyScholy",
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
        """Facets describe the live board only - archived rows must not add
        dropdown options that no visible scholarship matches."""
        body = self.client.get("/api/scholarships/facets/").json()
        countries = {row["value"] for row in body["countries"]}
        self.assertEqual(countries, {"United Kingdom", "Rwanda"})
        self.assertTrue(all("count" in row for row in body["degree_levels"]))

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
                subject="Welcome to MyScholy",
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
                subject="Reset your MyScholy password",
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
                subject="MyScholy contact form: Mallory",
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
            "author": "MyScholy",
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
