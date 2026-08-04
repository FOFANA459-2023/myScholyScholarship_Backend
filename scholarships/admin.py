from django.contrib import admin

from .models import Admin, ContactMessage, Scholarship, Student


@admin.register(Scholarship)
class ScholarshipAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "host_country",
        "degree_level",
        "deadline",
        "author",
        "is_active",
        "created_at",
    )
    list_filter = ("is_active", "degree_level", "host_country", "created_at")
    search_fields = ("name", "description", "author")
    list_editable = ("is_active",)
    list_per_page = 50
    date_hierarchy = "created_at"
    ordering = ("-created_at",)


@admin.register(Student)
class StudentAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "phone",
        "country_of_citizenship",
        "country_of_residence",
        "education_level",
        "created_at",
    )
    list_filter = ("education_level", "country_of_residence", "created_at")
    search_fields = (
        "user__username",
        "user__email",
        "user__first_name",
        "user__last_name",
    )
    list_select_related = ("user",)
    autocomplete_fields = ("user",)


@admin.register(Admin)
class AdminAdmin(admin.ModelAdmin):
    list_display = ("user", "is_super_admin", "created_at")
    list_filter = ("is_super_admin", "created_at")
    search_fields = ("user__username", "user__email")
    list_select_related = ("user",)
    autocomplete_fields = ("user",)


@admin.register(ContactMessage)
class ContactMessageAdmin(admin.ModelAdmin):
    list_display = ("name", "email", "is_handled", "created_at")
    list_filter = ("is_handled", "created_at")
    search_fields = ("name", "email", "message")
    list_editable = ("is_handled",)
    readonly_fields = ("name", "email", "message", "created_at")
    date_hierarchy = "created_at"
