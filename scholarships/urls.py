from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from . import views

urlpatterns = [
    # Public scholarships
    path(
        "scholarships/",
        views.ScholarshipListCreateView.as_view(),
        name="scholarship-list-create",
    ),
    path(
        "scholarships/facets/",
        views.scholarship_facets,
        name="scholarship-facets",
    ),
    # Live scholarships similar to this one (detail-page suggestions).
    path(
        "scholarships/<slug:lookup>/similar/",
        views.scholarship_similar,
        name="scholarship-similar",
    ),
    # Social preview card image (og:image for shared detail links).
    path(
        "scholarships/<slug:lookup>/card.png",
        views.scholarship_card,
        name="scholarship-card",
    ),
    # Matches both the public slug ("chevening-scholarship") and, for old
    # bookmarks and already-sent digest emails, a numeric id. Must stay below
    # scholarships/facets/ so "facets" is never treated as a slug.
    path(
        "scholarships/<slug:lookup>/",
        views.ScholarshipDetailView.as_view(),
        name="scholarship-detail",
    ),
    # Authentication
    path("auth/token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("auth/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("auth/student/register/", views.student_register, name="student-register"),
    path("auth/admin/register/", views.admin_register, name="admin-register"),
    path("auth/login/", views.user_login, name="user-login"),
    path("auth/logout/", views.user_logout, name="user-logout"),
    path("auth/profile/", views.user_profile, name="user-profile"),
    path(
        "auth/password-reset/",
        views.password_reset_request,
        name="password-reset-request",
    ),
    path(
        "auth/password-reset/confirm/",
        views.password_reset_confirm,
        name="password-reset-confirm",
    ),
    # Admin: scholarships
    path("admin/scholarships/", views.admin_scholarships, name="admin-scholarships"),
    path(
        "admin/scholarships/export/",
        views.export_scholarships_csv,
        name="export-scholarships-csv",
    ),
    path(
        "admin/scholarships/<int:pk>/",
        views.admin_scholarship_detail,
        name="admin-scholarship-detail",
    ),
    path(
        "admin/scholarships/<int:pk>/repost/",
        views.admin_scholarship_repost,
        name="admin-scholarship-repost",
    ),
    # Admin: users
    path("admins/", views.admin_users, name="admin-users"),
    path("admins/<int:user_id>/", views.delete_admin_user, name="admin-user-detail"),
    # Admin: dashboard
    path("admin/statistics/", views.admin_statistics, name="admin-statistics"),
    path("admin/users/", views.admin_user_directory, name="admin-user-directory"),
    path("admin/users/export/", views.export_users_csv, name="export-users-csv"),
    path("admin/contact/", views.contact_messages, name="admin-contact-messages"),
    path(
        "admin/contact/<int:pk>/",
        views.contact_message_detail,
        name="admin-contact-message-detail",
    ),
    path(
        "admin/contact/<int:pk>/reply/",
        views.contact_message_reply,
        name="admin-contact-message-reply",
    ),
    path("admin/messages/", views.outbound_messages, name="admin-messages"),
    # Public contact form
    path("contact/", views.contact_message, name="contact-message"),
    # Site assistant (Gemini-backed popup bot)
    path("assistant/", views.assistant_status, name="assistant-status"),
    path("assistant/chat/", views.assistant_chat, name="assistant-chat"),
    path(
        "assistant/assessment/",
        views.assistant_assessment,
        name="assistant-assessment",
    ),
    # Admin AI helper: paste text -> auto-filled posting form
    path(
        "admin/assistant/extract-scholarship/",
        views.assistant_extract_scholarship,
        name="assistant-extract-scholarship",
    ),
]
