"""Permission classes.

Role lookups used to hit the database on every single authenticated request.
They are now resolved once and cached per user; any change to a User, Admin or
Student row bumps the ``users`` cache namespace (see signals.py), so a
promotion or demotion takes effect on the next request.
"""

from rest_framework.permissions import SAFE_METHODS, BasePermission

from .cache import NS_USERS, TTL_PERMISSION, cached, make_key
from .models import Admin, Student

ANONYMOUS_ROLE = {"is_admin": False, "is_super_admin": False, "is_student": False}


def role_for(user):
    """Return ``{'is_admin', 'is_super_admin', 'is_student'}`` for a user."""
    if not user or not user.is_authenticated:
        return ANONYMOUS_ROLE

    def compute():
        profile = Admin.objects.filter(user=user).values("is_super_admin").first()
        is_admin = bool(profile) or user.is_staff or user.is_superuser
        is_super_admin = user.is_superuser or bool(profile and profile["is_super_admin"])
        return {
            "is_admin": is_admin,
            "is_super_admin": is_super_admin,
            "is_student": not is_admin and Student.objects.filter(user=user).exists(),
        }

    return cached(make_key(NS_USERS, "role", user_id=user.pk), TTL_PERMISSION, compute)


class IsAdmin(BasePermission):
    """Admins (custom Admin model) and Django staff/superusers."""

    message = "Administrator access is required."

    def has_permission(self, request, view):
        return role_for(request.user)["is_admin"]


class IsSuperAdmin(BasePermission):
    """Super admins only (Admin.is_super_admin or Django superuser)."""

    message = "Super administrator access is required."

    def has_permission(self, request, view):
        return role_for(request.user)["is_super_admin"]


class IsStudent(BasePermission):
    """Users with a Student profile who are not staff."""

    def has_permission(self, request, view):
        return role_for(request.user)["is_student"]


class IsAdminOrReadOnly(BasePermission):
    """Read for anyone; write only for admins."""

    message = "Administrator access is required to modify scholarships."

    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            return True
        return role_for(request.user)["is_admin"]
