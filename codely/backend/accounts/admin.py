from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from accounts.models import User


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ["username", "email", "xp", "level", "streak", "hearts"]
    fieldsets = BaseUserAdmin.fieldsets + (
        ("Gamification", {"fields": ("xp", "streak", "hearts", "last_activity_date", "avatar", "bio")}),
        ("Notifications", {"fields": ("reminder_enabled", "reminder_hour")}),
    )
