from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin

from .models import User


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    list_display = ("username", "email", "xp", "hearts", "streak", "is_staff")
    fieldsets = DjangoUserAdmin.fieldsets + (
        ("Gamification", {"fields": ("xp", "hearts", "streak", "last_activity_date", "avatar")}),
    )
