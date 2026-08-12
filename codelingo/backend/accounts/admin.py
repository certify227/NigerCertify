from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import User


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = (
        "username",
        "email",
        "xp",
        "gems",
        "hearts",
        "streak_count",
        "is_staff",
    )
    fieldsets = BaseUserAdmin.fieldsets + (
        (
            "Gamification",
            {
                "fields": (
                    "xp",
                    "gems",
                    "hearts",
                    "streak_count",
                    "last_activity_date",
                    "daily_goal_xp",
                    "avatar",
                )
            },
        ),
    )
