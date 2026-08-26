from django.contrib import admin

from .models import HotspotLoginTemplate, HotspotProfile, Voucher, VoucherBatch


@admin.register(HotspotLoginTemplate)
class HotspotLoginTemplateAdmin(admin.ModelAdmin):
    list_display = ("name", "owner", "is_system", "is_active")
    list_filter = ("is_system", "is_active")
    prepopulated_fields = {"slug": ("name",)}


@admin.register(HotspotProfile)
class HotspotProfileAdmin(admin.ModelAdmin):
    list_display = ("name", "router", "mikrotik_profile", "price", "is_active")
    list_filter = ("is_active", "router")


@admin.register(VoucherBatch)
class VoucherBatchAdmin(admin.ModelAdmin):
    list_display = ("pk", "router", "profile", "quantity", "total_price", "created_at")
    list_filter = ("router",)


@admin.register(Voucher)
class VoucherAdmin(admin.ModelAdmin):
    list_display = ("code", "router", "profile", "status", "sold_price", "created_at")
    list_filter = ("status", "router")
    search_fields = ("code", "username")
