from rest_framework.permissions import BasePermission, SAFE_METHODS
from .models import Admin, Student


class IsAdmin(BasePermission):
    """Allow access only to users who are admins (custom Admin model) or Django staff/superusers."""
    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated:
            return False
        if user.is_staff or user.is_superuser:
            return True
        return Admin.objects.filter(user=user).exists()


class IsSuperAdmin(BasePermission):
    """Allow access only to super admins (either custom Admin.is_super_admin or Django superuser)."""
    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated:
            return False
        if user.is_superuser:
            return True
        try:
            admin = Admin.objects.get(user=user)
            return admin.is_super_admin
        except Admin.DoesNotExist:
            return False


class IsStudent(BasePermission):
    """Allow access only to users with a Student profile and not staff/superuser/admin."""
    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated:
            return False
        if user.is_staff or user.is_superuser:
            return False
        return Student.objects.filter(user=user).exists()


class IsAdminOrReadOnly(BasePermission):
    """Read for anyone; write only for admins/superadmins."""
    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            return True
        user = request.user
        if not user or not user.is_authenticated:
            return False
        if user.is_staff or user.is_superuser:
            return True
        return Admin.objects.filter(user=user).exists()
