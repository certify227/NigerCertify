from django.contrib import admin

from .models import Router


@admin.register(Router)
class RouterAdmin(admin.ModelAdmin):
    list_display = ("name", "owner", "host", "connection_status", "is_active")
    list_filter = ("connection_status", "is_active")
    search_fields = ("name", "host", "owner__username")
