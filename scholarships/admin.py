from django.contrib import admin
from .models import Scholarship, Student, Admin

@admin.register(Scholarship)
class ScholarshipAdmin(admin.ModelAdmin):
    list_display = ('name', 'host_country', 'degree_level', 'deadline', 'author', 'is_active', 'created_at')
    list_filter = ('host_country', 'degree_level', 'is_active', 'created_at')
    search_fields = ('name', 'description', 'author')
    list_editable = ('is_active',)
    ordering = ('-created_at',)

@admin.register(Student)
class StudentAdmin(admin.ModelAdmin):
    list_display = ('user', 'phone', 'country', 'created_at')
    list_filter = ('country', 'created_at')
    search_fields = ('user__username', 'user__email', 'user__first_name', 'user__last_name')

@admin.register(Admin)
class AdminAdmin(admin.ModelAdmin):
    list_display = ('user', 'is_super_admin', 'created_at')
    list_filter = ('is_super_admin', 'created_at')
    search_fields = ('user__username', 'user__email')
