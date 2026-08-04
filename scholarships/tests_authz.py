"""Role-based authorization and token-lifecycle verification.

The full permission matrix in one place: anonymous, student, admin and super
admin against every protected surface, plus the SimpleJWT lifecycle rules -
logout blacklists the refresh token, rotation blacklists the replaced token,
and access tokens carry the configured expiry.
"""

from django.conf import settings
from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from .models import Admin, Student


def bearer(client, user):
    """Authenticate an APIClient as a user via a real JWT."""
    token = RefreshToken.for_user(user)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")


class RoleAuthorizationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        student_user = User.objects.create_user("student1", "s@example.com", "x")
        Student.objects.create(
            user=student_user,
            phone="",
            country_of_citizenship="Liberia",
            country_of_residence="Ghana",
            education_level="undergraduate",
        )
        admin_user = User.objects.create_user("admin1", "a@example.com", "x")
        Admin.objects.create(user=admin_user, is_super_admin=False)
        super_user = User.objects.create_user("super1", "sa@example.com", "x")
        Admin.objects.create(user=super_user, is_super_admin=True)

        cls.student_user = student_user
        cls.admin_user = admin_user
        cls.super_user = super_user

    def setUp(self):
        cache.clear()  # role_for() caches per user; tests must not leak roles
        self.client = APIClient()

    ADMIN_ONLY_GETS = [
        "/api/admin/scholarships/",
        "/api/admin/statistics/",
        "/api/admins/",
        "/api/admin/contact/",
        "/api/admin/users/export/",
        "/api/admin/scholarships/export/",
    ]

    def test_anonymous_is_rejected_from_admin_endpoints(self):
        for url in self.ADMIN_ONLY_GETS:
            response = self.client.get(url)
            self.assertEqual(response.status_code, 401, url)

    def test_student_is_rejected_from_admin_endpoints(self):
        bearer(self.client, self.student_user)
        for url in self.ADMIN_ONLY_GETS:
            response = self.client.get(url)
            self.assertEqual(response.status_code, 403, url)

    def test_anonymous_cannot_reach_profile_or_logout(self):
        self.assertEqual(self.client.get("/api/auth/profile/").status_code, 401)
        self.assertEqual(
            self.client.post("/api/auth/logout/", {"refresh": "x"}).status_code, 401
        )

    def test_admin_can_read_admin_surfaces(self):
        bearer(self.client, self.admin_user)
        for url in ["/api/admin/scholarships/", "/api/admin/statistics/"]:
            self.assertEqual(self.client.get(url).status_code, 200, url)

    def test_admin_can_add_admins_but_not_list_them(self):
        """A regular admin may grow the team, but must not be able to
        enumerate who the other administrators are."""
        bearer(self.client, self.admin_user)
        self.assertEqual(self.client.get("/api/admins/").status_code, 403)
        response = self.client.post(
            "/api/admins/",
            {
                "user": {
                    "username": "newadmin",
                    "email": "na@example.com",
                    "password": "SafePass123",
                    "first_name": "New",
                    "last_name": "Admin",
                },
            },
            format="json",
        )
        self.assertEqual(response.status_code, 201, response.content)

    def test_super_admin_can_list_admins(self):
        bearer(self.client, self.super_user)
        self.assertEqual(self.client.get("/api/admins/").status_code, 200)

    def test_admin_cannot_modify_or_delete_admin_accounts(self):
        bearer(self.client, self.admin_user)
        target = self.super_user.id
        self.assertEqual(
            self.client.patch(
                f"/api/admins/{target}/", {"first_name": "X"}, format="json"
            ).status_code,
            403,
        )
        self.assertEqual(self.client.delete(f"/api/admins/{target}/").status_code, 403)

    def test_admin_cannot_create_super_admin(self):
        bearer(self.client, self.admin_user)
        response = self.client.post(
            "/api/admins/",
            {
                "is_super_admin": True,
                "user": {
                    "username": "newsuper",
                    "email": "ns@example.com",
                    "password": "SafePass123",
                    "first_name": "New",
                    "last_name": "Super",
                },
            },
            format="json",
        )
        self.assertEqual(response.status_code, 403)

    def test_super_admin_can_modify_admins_but_not_delete_supers(self):
        bearer(self.client, self.super_user)
        response = self.client.patch(
            f"/api/admins/{self.admin_user.id}/", {"first_name": "Renamed"}, format="json"
        )
        self.assertEqual(response.status_code, 200)

        other_super = User.objects.create_user("super2", "sa2@example.com", "x")
        Admin.objects.create(user=other_super, is_super_admin=True)
        cache.clear()
        self.assertEqual(
            self.client.delete(f"/api/admins/{other_super.id}/").status_code, 403
        )

    def test_scholarship_writes_require_admin_but_reads_are_public(self):
        self.assertEqual(self.client.get("/api/scholarships/").status_code, 200)
        payload = {"name": "X"}
        self.assertIn(
            self.client.post("/api/scholarships/", payload, format="json").status_code,
            (401, 403),
        )
        bearer(self.client, self.student_user)
        self.assertEqual(
            self.client.post("/api/scholarships/", payload, format="json").status_code,
            403,
        )


class TokenLifecycleTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.user = User.objects.create_user("tok", "tok@example.com", "x")

    def test_logout_blacklists_the_refresh_token(self):
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
        response = self.client.post(
            "/api/auth/logout/", {"refresh": str(refresh)}, format="json"
        )
        self.assertEqual(response.status_code, 200)

        # The blacklisted token can no longer mint access tokens.
        self.client.credentials()
        response = self.client.post(
            "/api/auth/token/refresh/", {"refresh": str(refresh)}, format="json"
        )
        self.assertEqual(response.status_code, 401)

    def test_rotation_blacklists_the_replaced_refresh_token(self):
        old = str(RefreshToken.for_user(self.user))
        first = self.client.post(
            "/api/auth/token/refresh/", {"refresh": old}, format="json"
        )
        self.assertEqual(first.status_code, 200)
        # Rotation is on, so a replacement refresh token is issued...
        self.assertIn("refresh", first.json())
        # ...and the one it replaced is dead.
        second = self.client.post(
            "/api/auth/token/refresh/", {"refresh": old}, format="json"
        )
        self.assertEqual(second.status_code, 401)

    def test_access_token_carries_the_configured_expiry(self):
        token = AccessToken.for_user(self.user)
        lifetime = token["exp"] - token["iat"]
        expected = settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"].total_seconds()
        self.assertEqual(lifetime, expected)

    def test_expired_access_token_is_rejected(self):
        token = AccessToken.for_user(self.user)
        token.set_exp(lifetime=-settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"])
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        self.assertEqual(self.client.get("/api/auth/profile/").status_code, 401)
