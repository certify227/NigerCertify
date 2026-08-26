from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import TeamMembership, User


@admin.register(TeamMembership)
class TeamMembershipAdmin(admin.ModelAdmin):
    list_display = ("member", "owner", "role", "is_active")
    list_filter = ("role", "is_active")


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ("username", "email", "company_name", "city", "is_staff")
    fieldsets = BaseUserAdmin.fieldsets + (
        ("Profil opérateur", {"fields": ("company_name", "phone", "city", "country")}),
    )
    add_fieldsets = BaseUserAdmin.add_fieldsets + (
        ("Profil opérateur", {"fields": ("company_name", "phone", "city", "country")}),
    )
