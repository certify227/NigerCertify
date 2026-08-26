from django.contrib import admin

from .models import Plan, Subscription


@admin.register(Plan)
class PlanAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "price_monthly", "max_routers", "max_vouchers_month", "is_active")
    prepopulated_fields = {"slug": ("name",)}


@admin.register(Subscription)
class SubscriptionAdmin(admin.ModelAdmin):
    list_display = ("user", "plan", "status", "expires_at", "vouchers_used_this_month")
    list_filter = ("status", "plan")
    search_fields = ("user__username", "user__email")
