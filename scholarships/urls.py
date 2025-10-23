from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from . import views

urlpatterns = [
    # Scholarship URLs
    path(
        "scholarships/",
        views.ScholarshipListCreateView.as_view(),
        name="scholarship-list-create",
    ),
    path(
        "scholarships/<int:pk>/",
        views.ScholarshipDetailView.as_view(),
        name="scholarship-detail",
    ),
    # JWT Token URLs
    path("auth/token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("auth/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    # Authentication URLs
    path("auth/student/register/", views.student_register, name="student-register"),
    path("auth/admin/register/", views.admin_register, name="admin-register"),
    path("auth/login/", views.user_login, name="user-login"),
    path("auth/logout/", views.user_logout, name="user-logout"),
    path("auth/profile/", views.user_profile, name="user-profile"),
    # Admin URLs
    path("admin/scholarships/", views.admin_scholarships, name="admin-scholarships"),
    path(
        "admin/scholarships/<int:pk>/delete/",
        views.delete_scholarship,
        name="delete-scholarship",
    ),
    # Admin User Management
    path("admins/", views.admin_users, name="admin-users"),  # GET, POST
    path(
        "admins/<int:user_id>/", views.delete_admin_user, name="delete-admin-user"
    ),  # DELETE
    # Admin Statistics and Export
    path("admin/statistics/", views.admin_statistics, name="admin-statistics"),
    path("admin/users/export/", views.export_users_csv, name="export-users-csv"),
]
