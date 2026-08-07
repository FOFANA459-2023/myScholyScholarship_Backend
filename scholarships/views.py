"""API views.

Performance notes that apply throughout this module:

* Read endpoints are cached in a version-scoped namespace (see ``cache.py``).
  Any write bumps the version via model signals, so responses are never stale.
* Cached read endpoints also emit an ``ETag`` and ``Cache-Control``, letting
  Django's ConditionalGetMiddleware answer repeat requests with a 304 and no
  body at all.
* Aggregates run as a single query rather than one query per number.
* CSV exports stream instead of buffering the whole file in memory.
"""

import csv
import logging
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.db.models import Count, Q
from django.http import StreamingHttpResponse
from django.shortcuts import render
from django.utils import timezone
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework import generics, status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework_simplejwt.token_blacklist.models import (
    BlacklistedToken,
    OutstandingToken,
)
from rest_framework_simplejwt.tokens import RefreshToken

from . import assistant, emails
from .cache import (
    NS_SCHOLARSHIPS,
    NS_USERS,
    TTL_DETAIL,
    TTL_FACETS,
    TTL_LIST,
    TTL_ROSTER,
    TTL_STATISTICS,
    cached,
    etag_for,
    get_version,
    make_key,
)
from .filters import apply_filters, normalize_params, split_terms
from .models import Admin, ContactMessage, Scholarship, Student
from .pagination import ScholarshipPagination
from .permissions import IsAdmin, IsAdminOrReadOnly, IsSuperAdmin, role_for
from .serializers import (
    AdminSerializer,
    ContactMessageSerializer,
    LoginSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer,
    ScholarshipListSerializer,
    ScholarshipSerializer,
    StudentSerializer,
    UserSerializer,
)
from .throttling import AssessmentQuotaThrottle, ChatQuotaThrottle

# Always revalidate: a browser holding yesterday's list body must not keep
# serving it after an admin reposts or archives something. The version-scoped
# ETag makes revalidation nearly free - unchanged data answers with an empty
# 304, changed data arrives immediately. (The previous stale-while-revalidate
# window meant a reposted scholarship could take minutes to appear.)
PUBLIC_CACHE_CONTROL = "public, max-age=0, must-revalidate"
PRIVATE_CACHE_CONTROL = "private, max-age=0, must-revalidate"
# The filter dropdowns must never offer a value that is no longer in the data,
# so facets are always revalidated. The ETag is version-scoped, so an unchanged
# catalogue still answers with an empty 304.
REVALIDATE_CACHE_CONTROL = "public, max-age=0, must-revalidate"


def _apply_cache_headers(response, etag, cache_control=PUBLIC_CACHE_CONTROL):
    response["ETag"] = etag
    response["Cache-Control"] = cache_control
    response["Vary"] = "Accept, Authorization"
    return response


# ---------------------------------------------------------------------------
# Scholarships (public)
# ---------------------------------------------------------------------------


class ScholarshipListCreateView(generics.ListCreateAPIView):
    """GET: paginated, filtered, cached board. POST: admin-only create."""

    serializer_class = ScholarshipSerializer
    permission_classes = [IsAdminOrReadOnly]
    pagination_class = ScholarshipPagination

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["today"] = timezone.now().date()
        return context

    def get_queryset(self):
        is_admin = role_for(self.request.user)["is_admin"]
        params = normalize_params(self.request.query_params, allow_privileged=is_admin)
        return apply_filters(Scholarship.objects.list_fields(), params)

    def list(self, request, *args, **kwargs):
        is_admin = role_for(request.user)["is_admin"]
        # Only admins may request the archived/all views, so their responses
        # are cached (and tagged) separately from the public board.
        params = normalize_params(request.query_params, allow_privileged=is_admin)
        scope = {"admin": is_admin, **params}

        etag = etag_for(NS_SCHOLARSHIPS, **scope)
        key = make_key(NS_SCHOLARSHIPS, "list", **scope)

        def build():
            queryset = apply_filters(Scholarship.objects.list_fields(), params)
            page = self.paginate_queryset(queryset)
            serializer = ScholarshipListSerializer(
                page, many=True, context=self.get_serializer_context()
            )
            return self.get_paginated_response(serializer.data).data

        payload = cached(key, TTL_LIST, build)
        cache_control = PRIVATE_CACHE_CONTROL if is_admin else PUBLIC_CACHE_CONTROL
        return _apply_cache_headers(Response(payload), etag, cache_control)

    def perform_create(self, serializer):
        serializer.save()


class ScholarshipDetailView(generics.RetrieveUpdateDestroyAPIView):
    """GET is cached and public; write methods require an admin."""

    serializer_class = ScholarshipSerializer
    permission_classes = [IsAdminOrReadOnly]

    def get_queryset(self):
        # A scholarship an admin has hidden should not be readable by its id
        # either, so anonymous callers get a 404 rather than the record.
        if role_for(self.request.user)["is_admin"]:
            return Scholarship.objects.all()
        return Scholarship.objects.active()

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["today"] = timezone.now().date()
        return context

    def retrieve(self, request, *args, **kwargs):
        pk = kwargs["pk"]
        is_admin = role_for(request.user)["is_admin"]
        etag = etag_for(NS_SCHOLARSHIPS, detail=pk, admin=is_admin)
        key = make_key(NS_SCHOLARSHIPS, "detail", pk=pk, admin=is_admin)

        payload = cached(
            key,
            TTL_DETAIL,
            lambda: ScholarshipSerializer(
                self.get_object(), context=self.get_serializer_context()
            ).data,
        )
        cache_control = PRIVATE_CACHE_CONTROL if is_admin else PUBLIC_CACHE_CONTROL
        return _apply_cache_headers(Response(payload), etag, cache_control)


@api_view(["GET"])
@permission_classes([AllowAny])
def scholarship_facets(request):
    """Distinct countries and degree levels with counts, for the filter UI.

    Previously the client derived these by downloading every scholarship. This
    is two grouped queries, cached for 15 minutes.
    """
    etag = etag_for(NS_SCHOLARSHIPS, facets=True)
    key = make_key(NS_SCHOLARSHIPS, "facets")

    def build():
        # Facets describe what the public board can show: live rows only.
        # Archived scholarships must not add options no visible row matches.
        active = Scholarship.objects.active().open_for_application()

        def tally(field):
            """Count scholarships per individual term stored in ``field``.

            A row reading "Graduate, Postgraduate" counts towards both, so the
            dropdown offers each level once instead of listing every stored
            combination as its own option.
            """
            counts = {}
            labels = {}
            rows = active.values(field).annotate(count=Count("id"))
            for row in rows:
                for term in split_terms(row[field]):
                    key = term.casefold()
                    counts[key] = counts.get(key, 0) + row["count"]
                    labels.setdefault(key, term)
            return [
                {"value": labels[key], "count": counts[key]}
                for key in sorted(counts, key=lambda k: labels[k].lower())
            ]

        return {
            "countries": tally("host_country"),
            "degree_levels": tally("degree_level"),
        }

    return _apply_cache_headers(
        Response(cached(key, TTL_FACETS, build)), etag, REVALIDATE_CACHE_CONTROL
    )


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {"refresh": str(refresh), "access": str(refresh.access_token)}


def _serialize_login_user(user):
    """Build the user payload returned by login, using the cached role lookup
    instead of the try/except chain of queries this used to run."""
    role = role_for(user)
    user_type = "admin" if role["is_admin"] else "student"

    if role["is_admin"]:
        profile_row = Admin.objects.filter(user=user).values("id", "is_super_admin").first()
        profile = {
            "id": profile_row["id"] if profile_row else None,
            "is_super_admin": role["is_super_admin"],
        }
    else:
        profile = (
            Student.objects.filter(user=user)
            .values(
                "id",
                "phone",
                "country_of_citizenship",
                "country_of_residence",
                "education_level",
            )
            .first()
        )

    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "user_type": user_type,
        "profile": profile,
        "is_staff": user.is_staff,
        "is_superuser": user.is_superuser,
    }


class LoginThrottle(AnonRateThrottle):
    scope = "login"


@api_view(["POST"])
@permission_classes([AllowAny])
@throttle_classes([LoginThrottle])
def user_login(request):
    serializer = LoginSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    identifier = serializer.validated_data["username"].strip()
    password = serializer.validated_data["password"]

    # Resolve the account first (case-insensitively, by username or email) so
    # a failed sign-in can say what actually went wrong instead of a blanket
    # "invalid credentials".
    account = User.objects.filter(username__iexact=identifier).first()
    if not account and "@" in identifier:
        account = User.objects.filter(email__iexact=identifier).first()

    if not account:
        return Response(
            {
                "error": (
                    "We couldn't find an account with that email or username. "
                    "Double-check the spelling, or create a new account."
                )
            },
            status=status.HTTP_404_NOT_FOUND,
        )

    if not account.is_active:
        return Response(
            {
                "error": (
                    "This account has been deactivated. "
                    "Contact us if you think this is a mistake."
                )
            },
            status=status.HTTP_403_FORBIDDEN,
        )

    user = authenticate(username=account.username, password=password)
    if not user:
        return Response(
            {
                "error": (
                    "That password isn't right. Try again, or use "
                    "“Forgot password?” to reset it."
                )
            },
            status=status.HTTP_401_UNAUTHORIZED,
        )

    # SIMPLE_JWT's UPDATE_LAST_LOGIN only fires on its own token view, which
    # this custom login bypasses - so last_login must be stamped here or the
    # user directory would show stale (or never-set) sign-in dates.
    user.last_login = timezone.now()
    user.save(update_fields=["last_login"])

    return Response(
        {
            "message": "Login successful",
            "tokens": get_tokens_for_user(user),
            "user": _serialize_login_user(user),
        },
        status=status.HTTP_200_OK,
    )


@api_view(["POST"])
@permission_classes([AllowAny])
def student_register(request):
    serializer = StudentSerializer(data=request.data)
    if serializer.is_valid():
        student = serializer.save()
        # Registration signs the student straight in (tokens below), so it
        # counts as their first login.
        student.user.last_login = timezone.now()
        student.user.save(update_fields=["last_login"])
        emails.send_welcome_email(student.user)
        return Response(
            {
                "message": "Student registered successfully",
                "student_id": student.id,
                "tokens": get_tokens_for_user(student.user),
                "user": _serialize_login_user(student.user),
            },
            status=status.HTTP_201_CREATED,
        )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
@permission_classes([IsAdmin])
def admin_register(request):
    """Create an admin account. Restricted to existing admins - this endpoint
    used to be open to anonymous callers, which allowed anyone to grant
    themselves administrator access."""
    serializer = AdminSerializer(data=request.data)
    if serializer.is_valid():
        if serializer.validated_data.get("is_super_admin") and not role_for(
            request.user
        )["is_super_admin"]:
            return Response(
                {"error": "Only super admins can create super admins"},
                status=status.HTTP_403_FORBIDDEN,
            )
        admin = serializer.save()
        return Response(
            {"message": "Admin registered successfully", "admin_id": admin.id},
            status=status.HTTP_201_CREATED,
        )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def user_logout(request):
    refresh_token = request.data.get("refresh")
    if not refresh_token:
        return Response(
            {"error": "A refresh token is required."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    try:
        RefreshToken(refresh_token).blacklist()
    except Exception:
        return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)
    return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def user_profile(request):
    return Response(_serialize_login_user(request.user), status=status.HTTP_200_OK)


logger = logging.getLogger(__name__)


class PasswordResetThrottle(AnonRateThrottle):
    scope = "password_reset"


@api_view(["POST"])
@permission_classes([AllowAny])
@throttle_classes([PasswordResetThrottle])
def password_reset_request(request):
    """Email a signed, single-use reset link."""
    serializer = PasswordResetRequestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    email = serializer.validated_data["email"].strip()
    user = User.objects.filter(email__iexact=email, is_active=True).first()

    if not user:
        return Response(
            {
                "error": (
                    "We couldn't find an account with that email. "
                    "Check for typos, or create a new account instead."
                )
            },
            status=status.HTTP_404_NOT_FOUND,
        )

    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    link = f"{settings.FRONTEND_URL}/reset-password?uid={uid}&token={token}"
    # Fire and forget: the user should not be staring at a spinner while the
    # email provider round trip completes.
    emails.send_password_reset_email(user, link)

    return Response(
        {
            "message": (
                f"We've emailed a reset link to {user.email}. "
                "Check your inbox - and your spam folder, just in case. "
                "The link expires in 1 hour."
            )
        },
        status=status.HTTP_200_OK,
    )


@api_view(["POST"])
@permission_classes([AllowAny])
@throttle_classes([PasswordResetThrottle])
def password_reset_confirm(request):
    serializer = PasswordResetConfirmSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    try:
        user_id = force_str(urlsafe_base64_decode(serializer.validated_data["uid"]))
        user = User.objects.get(pk=user_id, is_active=True)
    except (User.DoesNotExist, ValueError, TypeError, OverflowError):
        user = None

    token = serializer.validated_data["token"]
    if not user or not default_token_generator.check_token(user, token):
        return Response(
            {"error": "This reset link is invalid or has expired. Please request a new one."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    new_password = serializer.validated_data["new_password"]
    try:
        # Validated here rather than in the serializer so the similarity
        # validator can compare against the user's name and email.
        validate_password(new_password, user=user)
    except DjangoValidationError as exc:
        return Response(
            {"new_password": exc.messages}, status=status.HTTP_400_BAD_REQUEST
        )

    user.set_password(new_password)
    user.save(update_fields=["password"])
    # Changing the password invalidates the token (it hashes the old password),
    # and blacklisting outstanding refresh tokens signs out existing sessions.
    for outstanding in OutstandingToken.objects.filter(user=user):
        BlacklistedToken.objects.get_or_create(token=outstanding)

    return Response(
        {"message": "Password reset successful. You can now sign in."},
        status=status.HTTP_200_OK,
    )


# ---------------------------------------------------------------------------
# Admin: scholarships
# ---------------------------------------------------------------------------


@api_view(["GET", "POST"])
@permission_classes([IsAdmin])
def admin_scholarships(request):
    """Admin listing and create.

    ``?view=live`` (default) matches the public board, ``?view=archived``
    returns hidden or expired rows, and ``?view=all`` returns everything.

    Cached like the public board: keys live in the versioned scholarship
    namespace, so any write invalidates them immediately and the response can
    never be stale. Headers stay private - only the server holds a copy.
    """
    if request.method == "GET":
        params = normalize_params(request.query_params, allow_privileged=True)
        etag = etag_for(NS_SCHOLARSHIPS, admin_list=True, **params)
        key = make_key(NS_SCHOLARSHIPS, "admin-list", **params)

        def build():
            queryset = apply_filters(Scholarship.objects.list_fields(), params)
            paginator = ScholarshipPagination()
            page = paginator.paginate_queryset(queryset, request)
            serializer = ScholarshipListSerializer(
                page, many=True, context={"today": timezone.now().date()}
            )
            return paginator.get_paginated_response(serializer.data).data

        payload = cached(key, TTL_LIST, build)
        return _apply_cache_headers(Response(payload), etag, PRIVATE_CACHE_CONTROL)

    serializer = ScholarshipSerializer(
        data=request.data, context={"today": timezone.now().date()}
    )
    if serializer.is_valid():
        # Post-time duplicate safety net: warn once (409) and require an
        # explicit confirm_duplicate=true resubmit to post anyway. Advisory -
        # no key, no candidates or a provider hiccup all fall through to a
        # normal save.
        if settings.GEMINI_API_KEY and not request.data.get("confirm_duplicate"):
            try:
                duplicate = assistant.find_possible_duplicate(
                    serializer.validated_data
                )
            except Exception:
                logger.exception("Duplicate check failed on create")
                duplicate = None
            if duplicate:
                return Response(
                    {
                        "error": (
                            "This scholarship likely already exists in the "
                            f"{'archive' if duplicate['status'] == 'archived' else 'live board'}"
                            f" as \"{duplicate['name']}\"."
                        ),
                        "duplicate": duplicate,
                    },
                    status=status.HTTP_409_CONFLICT,
                )
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET", "PUT", "PATCH", "DELETE"])
@permission_classes([IsAdmin])
def admin_scholarship_detail(request, pk):
    scholarship = Scholarship.objects.filter(pk=pk).first()
    if scholarship is None:
        return Response(
            {"error": "Scholarship not found"}, status=status.HTTP_404_NOT_FOUND
        )

    context = {"today": timezone.now().date()}

    if request.method == "GET":
        return Response(
            ScholarshipSerializer(scholarship, context=context).data,
            status=status.HTTP_200_OK,
        )

    if request.method in ("PUT", "PATCH"):
        serializer = ScholarshipSerializer(
            scholarship,
            data=request.data,
            partial=request.method == "PATCH",
            context=context,
        )
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    scholarship.delete()
    return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(["POST"])
@permission_classes([IsAdmin])
def admin_scholarship_repost(request, pk):
    """Return an archived scholarship to the live board.

    Reposting only makes sense while applications can still be submitted, so a
    past deadline is rejected with a message telling the admin what to do
    instead (edit the scholarship and extend the deadline first). The save
    fires the model signals, which invalidate every cached list at once.
    """
    scholarship = Scholarship.objects.filter(pk=pk).first()
    if scholarship is None:
        return Response(
            {"error": "Scholarship not found"}, status=status.HTTP_404_NOT_FOUND
        )

    today = timezone.now().date()
    if scholarship.deadline < today:
        return Response(
            {
                "error": (
                    "This scholarship cannot be reposted because its deadline "
                    "has passed. Edit it and set a new deadline first."
                )
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    if not scholarship.is_active:
        scholarship.is_active = True
        scholarship.save(update_fields=["is_active", "updated_at"])

    return Response(
        ScholarshipSerializer(scholarship, context={"today": today}).data,
        status=status.HTTP_200_OK,
    )


# ---------------------------------------------------------------------------
# Admin: user management
# ---------------------------------------------------------------------------


@api_view(["GET", "POST"])
@permission_classes([IsAdmin])
def admin_users(request):
    """POST (add an admin) is open to every admin; GET (the roster of who
    has access) is super-admin-only - a regular admin should not be able to
    enumerate the other administrators."""
    if request.method == "GET":
        if not role_for(request.user)["is_super_admin"]:
            return Response(
                {"error": "Super administrator access is required."},
                status=status.HTTP_403_FORBIDDEN,
            )
        # The management page polls this; never let a browser or proxy hold a
        # copy - freshness is handled by the server-side versioned cache.
        response = Response(_list_admin_users(), status=status.HTTP_200_OK)
        response["Cache-Control"] = "private, no-store"
        return response
    return _create_admin_user(request)


def _list_admin_users():
    """Every admin-ish account in one query.

    The previous implementation looped over staff users and ran an
    ``Admin.objects.filter(...).exists()`` per row.
    """
    key = make_key(NS_USERS, "admin-roster")

    def build():
        rows = (
            # Anything the database considers an admin: an Admin profile row,
            # Django staff, or a superuser flag set directly on the account.
            User.objects.filter(
                Q(admin__isnull=False) | Q(is_staff=True) | Q(is_superuser=True)
            )
            .distinct()
            .select_related("admin")
            .order_by("username")
        )
        return [
            {
                "admin_id": getattr(getattr(user, "admin", None), "id", None),
                "user_id": user.id,
                "username": user.username,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "is_super_admin": bool(
                    getattr(getattr(user, "admin", None), "is_super_admin", False)
                    or user.is_superuser
                ),
                "is_staff": user.is_staff,
                "is_superuser": user.is_superuser,
            }
            for user in rows
        ]

    return cached(key, TTL_ROSTER, build)


def _create_admin_user(request):
    user_data = request.data.get("user")
    if not isinstance(user_data, dict):
        return Response(
            {"error": "User data required"}, status=status.HTTP_400_BAD_REQUEST
        )

    wants_super_admin = str(request.data.get("is_super_admin", "")).lower() in {
        "true",
        "1",
        "yes",
    } or request.data.get("is_super_admin") is True

    requester_is_super_admin = role_for(request.user)["is_super_admin"]
    if wants_super_admin and not requester_is_super_admin:
        return Response(
            {"error": "Only super admins can create super admins"},
            status=status.HTTP_403_FORBIDDEN,
        )

    username = (user_data.get("username") or "").strip()
    email = (user_data.get("email") or "").strip()
    if User.objects.filter(Q(username__iexact=username) | Q(email__iexact=email)).exists():
        return Response(
            {"error": "User with this username or email already exists"},
            status=status.HTTP_409_CONFLICT,
        )

    user_serializer = UserSerializer(data=user_data)
    if not user_serializer.is_valid():
        return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    with transaction.atomic():
        user = user_serializer.save()
        user.is_staff = True
        user.is_superuser = bool(wants_super_admin and requester_is_super_admin)
        user.save(update_fields=["is_staff", "is_superuser"])
        admin = Admin.objects.create(
            user=user, is_super_admin=bool(wants_super_admin and requester_is_super_admin)
        )

    return Response(
        {
            "id": admin.id,
            "user_id": user.id,
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "is_super_admin": admin.is_super_admin,
            "is_staff": user.is_staff,
            "is_superuser": user.is_superuser,
        },
        status=status.HTTP_201_CREATED,
    )


@api_view(["PATCH", "DELETE"])
@permission_classes([IsAdmin])
def delete_admin_user(request, user_id):
    user = User.objects.filter(id=user_id).first()
    if user is None:
        return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    if not role_for(request.user)["is_super_admin"]:
        return Response(
            {"error": "Only super admins can modify admins"},
            status=status.HTTP_403_FORBIDDEN,
        )

    if request.method == "PATCH":
        return _update_admin_user(request, user)

    if user.id == request.user.id:
        return Response(
            {"error": "You cannot delete your own account"},
            status=status.HTTP_403_FORBIDDEN,
        )

    is_super = user.is_superuser or Admin.objects.filter(
        user=user, is_super_admin=True
    ).exists()
    if is_super:
        return Response(
            {"error": "Cannot delete super admin user"},
            status=status.HTTP_403_FORBIDDEN,
        )

    soft = str(
        request.query_params.get("soft") or request.data.get("soft") or ""
    ).lower() in {"true", "1", "yes"}

    with transaction.atomic():
        if soft:
            # Demote: keep the account, drop the admin privileges.
            Admin.objects.filter(user=user).delete()
            user.is_staff = False
            user.is_superuser = False
            user.save(update_fields=["is_staff", "is_superuser"])
            return Response(
                {"message": "Admin user demoted successfully"},
                status=status.HTTP_200_OK,
            )
        username, email = user.username, user.email
        user.delete()  # cascades to Admin/Student profiles

    return Response(
        {
            "message": "Admin user deleted successfully",
            "username": username,
            "email": email,
        },
        status=status.HTTP_200_OK,
    )


def _update_admin_user(request, user):
    updates = []
    for field in ("first_name", "last_name", "email"):
        value = request.data.get(field)
        if value is not None:
            setattr(user, field, value)
            updates.append(field)

    if not user.is_staff:
        user.is_staff = True
        updates.append("is_staff")

    is_super_admin = request.data.get("is_super_admin")
    if is_super_admin is not None:
        if isinstance(is_super_admin, str):
            is_super_admin = is_super_admin.lower() in {"true", "1", "yes"}
        is_super_admin = bool(is_super_admin)
        user.is_superuser = is_super_admin
        updates.append("is_superuser")
        Admin.objects.update_or_create(
            user=user, defaults={"is_super_admin": is_super_admin}
        )
    else:
        Admin.objects.get_or_create(user=user)

    if updates:
        user.save(update_fields=list(dict.fromkeys(updates)))

    return Response(
        {
            "message": "Admin user updated successfully",
            "user_id": user.id,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
            "is_superuser": user.is_superuser,
            "is_staff": user.is_staff,
        },
        status=status.HTTP_200_OK,
    )


# ---------------------------------------------------------------------------
# Admin: statistics and exports
# ---------------------------------------------------------------------------


@api_view(["GET"])
@permission_classes([IsAdmin])
def admin_statistics(request):
    """Dashboard numbers.

    This used to fire eleven separate queries on every page load. It is now
    three (scholarships, users, students) plus two grouped lookups, and the
    whole payload is cached for two minutes.

    The payload mixes user AND scholarship numbers, so the key and ETag embed
    both namespace versions - posting or archiving a scholarship refreshes
    the dashboard immediately instead of serving 304s until a user changes.
    """
    scholarship_version = get_version(NS_SCHOLARSHIPS)
    key = make_key(NS_USERS, "statistics", sv=scholarship_version)

    def build():
        today = timezone.now().date()
        start_of_week = today - timedelta(days=today.weekday())
        start_of_month = today.replace(day=1)
        start_of_year = today.replace(month=1, day=1)
        thirty_days_ago = timezone.now() - timedelta(days=30)

        scholarship_totals = Scholarship.objects.aggregate(
            total=Count("id"),
            active=Count("id", filter=Q(is_active=True)),
            recent=Count("id", filter=Q(created_at__gte=thirty_days_ago)),
            open_now=Count("id", filter=Q(is_active=True, deadline__gte=today)),
        )
        user_totals = User.objects.aggregate(
            total=Count("id"),
            weekly=Count("id", filter=Q(date_joined__date__gte=start_of_week)),
            monthly=Count("id", filter=Q(date_joined__date__gte=start_of_month)),
            yearly=Count("id", filter=Q(date_joined__date__gte=start_of_year)),
            students=Count("id", filter=Q(student__isnull=False)),
            admins=Count("id", filter=Q(admin__isnull=False)),
        )
        total_countries = (
            Student.objects.exclude(country_of_residence="")
            .values("country_of_residence")
            .distinct()
            .count()
        )
        scholarships_by_degree = list(
            Scholarship.objects.values("degree_level")
            .annotate(count=Count("id"))
            .order_by("-count")[:5]
        )

        return {
            "total_scholarships": scholarship_totals["total"],
            "active_scholarships": scholarship_totals["active"],
            "open_scholarships": scholarship_totals["open_now"],
            "recent_scholarships": scholarship_totals["recent"],
            "total_users": user_totals["total"],
            "total_students": user_totals["students"],
            "total_admins": user_totals["admins"],
            "weekly_signups": user_totals["weekly"],
            "monthly_signups": user_totals["monthly"],
            "yearly_signups": user_totals["yearly"],
            "total_countries": total_countries,
            "scholarships_by_degree": scholarships_by_degree,
        }

    payload = cached(key, TTL_STATISTICS, build)
    return _apply_cache_headers(
        Response(payload),
        etag_for(NS_USERS, stats=True, sv=scholarship_version),
        PRIVATE_CACHE_CONTROL,
    )


@api_view(["GET"])
@permission_classes([IsSuperAdmin])
def admin_user_directory(request):
    """Paginated, searchable roster of every account with its profile data -
    the on-screen counterpart of the users CSV export. Super admins only:
    regular admins manage scholarships, not people.

    Personal data handling: the payload is cached only server-side, in the
    versioned users namespace (any account write invalidates it, and the
    30-second TTL keeps even direct database edits fresh). The response is
    marked ``private, no-store`` so no browser or proxy ever keeps a copy,
    and the frontend deliberately skips its sessionStorage cache for it.
    """
    q = str(request.query_params.get("q", "")).strip()[:120]
    try:
        page = max(1, int(request.query_params.get("page", 1)))
    except (TypeError, ValueError):
        page = 1
    page_size = str(request.query_params.get("page_size", ""))

    key = make_key(NS_USERS, "directory", q=q, page=page, page_size=page_size)

    def build():
        rows = User.objects.select_related("student", "admin").order_by("-date_joined")
        if q:
            rows = rows.filter(
                Q(username__icontains=q)
                | Q(email__icontains=q)
                | Q(first_name__icontains=q)
                | Q(last_name__icontains=q)
            )

        paginator = ScholarshipPagination()
        page_rows = paginator.paginate_queryset(rows, request)

        def serialize(user):
            admin = getattr(user, "admin", None)
            student = getattr(user, "student", None)
            if admin is not None:
                user_type = "Super Admin" if admin.is_super_admin else "Admin"
            elif student is not None:
                user_type = "Student"
            else:
                user_type = "User"
            return {
                "id": user.id,
                "username": user.username,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "email": user.email,
                "user_type": user_type,
                "phone": student.phone if student else "",
                "country_of_citizenship": student.country_of_citizenship if student else "",
                "country_of_residence": student.country_of_residence if student else "",
                "education_level": student.get_education_level_display() if student else "",
                "date_joined": user.date_joined,
                "last_login": user.last_login,
                "is_active": user.is_active,
            }

        return paginator.get_paginated_response(
            [serialize(user) for user in page_rows]
        ).data

    response = Response(cached(key, TTL_ROSTER, build), status=status.HTTP_200_OK)
    response["Cache-Control"] = "private, no-store"
    return response


class _CsvEcho:
    """File-like object whose write() returns the value, so csv.writer output
    can be yielded straight into a StreamingHttpResponse."""

    def write(self, value):
        return value


def _stream_csv(filename, header, rows):
    writer = csv.writer(_CsvEcho())

    def generate():
        yield writer.writerow(header)
        for row in rows:
            yield writer.writerow(row)

    response = StreamingHttpResponse(generate(), content_type="text/csv")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


@api_view(["GET"])
@permission_classes([IsSuperAdmin])
def export_users_csv(request):
    """Every account with its role and, for students, the profile fields the
    signup form collects - so the export is usable for outreach without a
    second lookup. Super admins only, same as the on-screen directory."""
    stamp = timezone.now().strftime("%Y-%m-%d")

    def rows():
        queryset = (
            User.objects.select_related("student", "admin")
            .order_by("id")
            .iterator(chunk_size=500)
        )
        for user in queryset:
            admin = getattr(user, "admin", None)
            student = getattr(user, "student", None)
            if admin is not None:
                user_type = "Super Admin" if admin.is_super_admin else "Admin"
            elif student is not None:
                user_type = "Student"
            else:
                user_type = "User"
            yield [
                user.id,
                user.username,
                user.first_name,
                user.last_name,
                user.email,
                user_type,
                student.phone if student else "",
                student.country_of_citizenship if student else "",
                student.country_of_residence if student else "",
                student.get_education_level_display() if student else "",
                user.date_joined.strftime("%Y-%m-%d %H:%M:%S") if user.date_joined else "",
                user.last_login.strftime("%Y-%m-%d %H:%M:%S") if user.last_login else "",
                "Yes" if user.is_active else "No",
            ]

    return _stream_csv(
        f"users_export_{stamp}.csv",
        [
            "ID",
            "Username",
            "First Name",
            "Last Name",
            "Email",
            "User Type",
            "Phone",
            "Country of Citizenship",
            "Country of Residence",
            "Education Level",
            "Date Joined",
            "Last Login",
            "Is Active",
        ],
        rows(),
    )


@api_view(["GET"])
@permission_classes([IsAdmin])
def export_scholarships_csv(request):
    """Live scholarships only (active, deadline still ahead) - the same rows
    the public board shows - with exactly the columns the team works from."""
    stamp = timezone.now().strftime("%Y-%m-%d")
    rows = (
        Scholarship.objects.active()
        .open_for_application()
        .order_by("-created_at")
        .values_list("name", "host_country", "degree_level", "deadline", "link")
        .iterator(chunk_size=500)
    )
    return _stream_csv(
        f"active_scholarships_{stamp}.csv",
        ["Name", "Host Country", "Degree Level", "Deadline", "Link"],
        rows,
    )


# ---------------------------------------------------------------------------
# Contact
# ---------------------------------------------------------------------------


class AssistantThrottle(AnonRateThrottle):
    scope = "assistant"


@api_view(["GET"])
@permission_classes([AllowAny])
def assistant_status(request):
    """Whether the site assistant is configured. The widget hides when not."""
    response = Response({"enabled": bool(settings.GEMINI_API_KEY)})
    response["Cache-Control"] = "public, max-age=300"
    return response


@api_view(["POST"])
@permission_classes([AllowAny])
@throttle_classes([AssistantThrottle, ChatQuotaThrottle])
def assistant_chat(request):
    """One turn of the popup assistant conversation.

    The Gemini key stays server-side; this endpoint validates the payload,
    grounds the model with live scholarship rows and relays the reply. Chat
    content is never cached or stored.
    """
    if not settings.GEMINI_API_KEY:
        return Response(
            {"error": "The assistant is not available right now."},
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    message = request.data.get("message")
    if not isinstance(message, str) or not message.strip():
        return Response(
            {"error": "Please type a question."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    message = message.strip()
    if len(message) > 1000:
        return Response(
            {"error": "Please keep questions under 1000 characters."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    history = request.data.get("history") or []
    if not isinstance(history, list):
        history = []
    cleaned_history = []
    for turn in history[-10:]:
        if not isinstance(turn, dict):
            continue
        role = turn.get("role")
        text = turn.get("text")
        if role in ("user", "model") and isinstance(text, str) and text.strip():
            cleaned_history.append({"role": role, "text": text.strip()[:2000]})

    try:
        reply = assistant.ask(message, cleaned_history)
    except assistant.AssistantError as exc:
        return Response(
            {"error": str(exc)},
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    response = Response({"reply": reply})
    response["Cache-Control"] = "private, no-store"
    return response


@api_view(["POST"])
@permission_classes([AllowAny])
@throttle_classes([AssessmentQuotaThrottle])
def assistant_assessment(request):
    """Personalized fit-assessment result, grounded with live scholarships.

    Public like the quiz itself; the same scoped throttle as the chat bot
    protects the provider quota. Answers are quiz option values only - no
    personal data reaches the provider.
    """
    if not settings.GEMINI_API_KEY:
        return Response(
            {"error": "Personalized results are not available right now."},
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    answers = request.data.get("answers")
    if not isinstance(answers, dict):
        return Response(
            {"error": "Complete the assessment first."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    cleaned = {}
    for key in assistant.ASSESSMENT_KEYS:
        value = answers.get(key)
        if isinstance(value, str) and value.strip():
            cleaned[key] = value.strip()[:40]
    if not cleaned.get("level"):
        return Response(
            {"error": "Complete the assessment first."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        result = assistant.personalized_assessment(cleaned)
    except assistant.AssistantError as exc:
        return Response(
            {"error": str(exc)},
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    response = Response(result)
    response["Cache-Control"] = "private, no-store"
    return response


@api_view(["POST"])
@permission_classes([IsAdmin])
def assistant_extract_scholarship(request):
    """Admin helper: extract posting-form fields from pasted announcement text.

    Backing for the "paste & auto-fill" box on the post-scholarship form. The
    model only reads the pasted text; fields it cannot find come back as empty
    strings, and the admin reviews everything before posting.
    """
    if not settings.GEMINI_API_KEY:
        return Response(
            {"error": "The AI helper is not configured on this server."},
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    pdf = request.FILES.get("pdf")
    url = request.data.get("url")
    text = request.data.get("text")

    try:
        if pdf is not None:
            if pdf.size > 10 * 1024 * 1024:
                return Response(
                    {"error": "PDFs up to 10 MB are supported."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            pdf_bytes = pdf.read()
            if pdf_bytes[:5] != b"%PDF-":
                return Response(
                    {"error": "That file does not look like a PDF."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            fields = assistant.extract_scholarship(pdf_bytes=pdf_bytes)
        elif isinstance(url, str) and url.strip():
            kind, content = assistant.fetch_url(url.strip())
            if kind == "pdf":
                fields = assistant.extract_scholarship(pdf_bytes=content)
            else:
                if len(content) < 40:
                    return Response(
                        {"error": "That page has no readable text. Copy the text and paste it instead."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                fields = assistant.extract_scholarship(text=content[:20000])
        elif isinstance(text, str) and len(text.strip()) >= 40:
            fields = assistant.extract_scholarship(text=text.strip()[:20000])
        else:
            return Response(
                {"error": "Paste the announcement text (at least a few sentences), a link, or a PDF first."},
                status=status.HTTP_400_BAD_REQUEST,
            )
    except assistant.AssistantError as exc:
        # Bad/unreachable/private URLs are caller errors; provider failures
        # (from _generate) also land here and read fine as a 400 message.
        return Response(
            {"error": str(exc)},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Advisory only: warn when the board (live or archive) already has this
    # scholarship, but never let the check break a successful extraction.
    try:
        duplicate = assistant.find_possible_duplicate(fields)
    except Exception:
        logger.exception("Duplicate check failed")
        duplicate = None

    response = Response({"fields": fields, "duplicate": duplicate})
    response["Cache-Control"] = "private, no-store"
    return response


class ContactThrottle(AnonRateThrottle):
    scope = "contact"


@api_view(["POST"])
@permission_classes([AllowAny])
@throttle_classes([ContactThrottle])
def contact_message(request):
    """Public contact form. Rate limited so the inbox cannot be flooded."""
    serializer = ContactMessageSerializer(data=request.data)
    if serializer.is_valid():
        message = serializer.save()
        # Stored first, emailed second: a delivery problem must never lose the
        # message, and the sender should not wait on the provider round trip.
        emails.send_contact_notification(message)
        return Response(
            {"message": "Thanks for reaching out - we'll be in touch shortly."},
            status=status.HTTP_201_CREATED,
        )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET"])
@permission_classes([IsAdmin])
def contact_messages(request):
    queryset = ContactMessage.objects.all()
    paginator = ScholarshipPagination()
    page = paginator.paginate_queryset(queryset, request)
    return paginator.get_paginated_response(
        ContactMessageSerializer(page, many=True).data
    )


# ---------------------------------------------------------------------------
# Root
# ---------------------------------------------------------------------------

API_INFO = {
    "message": "Welcome to the MyScholy API",
    "version": "2.0",
    "description": "REST API powering the MyScholy scholarship board",
    "status": "operational",
    "endpoints": {
        "authentication": {
            "login": "/api/auth/login/",
            "logout": "/api/auth/logout/",
            "register_student": "/api/auth/student/register/",
            "register_admin": "/api/auth/admin/register/",
            "profile": "/api/auth/profile/",
            "token_refresh": "/api/auth/token/refresh/",
        },
        "scholarships": {
            "list": "/api/scholarships/",
            "detail": "/api/scholarships/{id}/",
            "facets": "/api/scholarships/facets/",
        },
        "admin": {
            "scholarships": "/api/admin/scholarships/",
            "scholarship_detail": "/api/admin/scholarships/{id}/",
            "scholarship_repost": "/api/admin/scholarships/{id}/repost/",
            "statistics": "/api/admin/statistics/",
            "users": "/api/admins/",
            "user_detail": "/api/admins/{user_id}/",
            "user_directory": "/api/admin/users/",
            "export_users": "/api/admin/users/export/",
            "export_scholarships": "/api/admin/scholarships/export/",
            "contact_messages": "/api/admin/contact/",
        },
        "public": {"contact": "/api/contact/"},
    },
}


@api_view(["GET"])
@permission_classes([AllowAny])
def home(request):
    """API index. Renders a template for browsers, JSON for API clients."""
    accept = request.META.get("HTTP_ACCEPT", "")
    if "text/html" in accept and "application/json" not in accept:
        response = render(request, "scholarships/api_index.html", {"info": API_INFO})
        response["Cache-Control"] = "public, max-age=3600"
        return response
    return Response(API_INFO, status=status.HTTP_200_OK)
