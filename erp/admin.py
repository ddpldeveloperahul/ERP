from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from erp.models import User, EmailOTP, Lead, ScheduleCallback, EmailCampaign


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    list_display = (
        "email",
        "first_name",
        "last_name",
        "role",
        "is_active",
        "is_email_verified",
        "is_staff",
    )

    list_filter = (
        "role",
        "is_active",
        "is_email_verified",
        "is_staff",
    )

    ordering = ("email",)

    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Personal Info", {
            "fields": ("first_name", "last_name")
        }),
        ("ERP Role & Verification", {
            "fields": ("role", "is_email_verified")
        }),
        ("Permissions", {
            "fields": (
                "is_active",
                "is_staff",
                "is_superuser",
                "groups",
                "user_permissions",
            )
        }),
        ("Important Dates", {
            "fields": ("last_login", "date_joined")
        }),
    )

    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": (
                "email",
                "first_name",
                "last_name",
                "role",
                "is_email_verified",
                "password1",
                "password2",
            ),
        }),
    )

    search_fields = ("email", "first_name", "last_name")


@admin.register(EmailOTP)
class EmailOTPAdmin(admin.ModelAdmin):
    list_display = (
        "email",
        "otp",
        "purpose",
        "created_at",
        "expires_at",
        "is_verified",
    )
    list_filter = (
        "purpose",
        "is_verified",
        "created_at",
    )
    search_fields = (
        "email",
        "otp",
    )
    readonly_fields = (
        "created_at",
    )


@admin.register(Lead)
class LeadAdmin(admin.ModelAdmin):
    list_display = (
        "lead_id",
        "client_full_name",
        "client_company_name",
        "client_email",
        "client_contact_number",
        "client_is",
        "lead_type",
        "project_category",
        "status",
        "next_follow_up",
        "lead_generated_from",
        "created_by",
        "created_at",
    )
    list_filter = (
        "status",
        "client_is",
        "lead_type",
        "project_category",
        "next_follow_up",
        "lead_generated_from",
        "created_at",
    )
    search_fields = (
        "client_full_name",
        "client_company_name",
        "client_email",
        "client_contact_number",
        "country_name",
        "requirement_description",
    )
    readonly_fields = (
        "created_at",
        "updated_at",
    )



@admin.register(ScheduleCallback)
class ScheduleCallbackAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "lead",
        "phone",
        "date_time",
        "type",
        "status",
        "created_by",
        "created_at",
    )
    list_filter = (
        "type",
        "status",
        "date_time",
        "created_at",
    )
    search_fields = (
        "lead__client_full_name",
        "lead__client_company_name",
        "phone",
        "notes",
    )
    readonly_fields = (
        "created_at",
        "updated_at",
    )


@admin.register(EmailCampaign)
class EmailCampaignAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "name",
        "lead_type",
        "category",
        "country",
        "client_is",
        "sales_status",
        "status",
        "total_leads_matched",
        "created_by",
        "created_at",
    )
    list_filter = (
        "status",
        "lead_type",
        "category",
        "country",
        "client_is",
        "created_at",
    )
    search_fields = (
        "name",
        "subject",
        "message",
        "category",
        "country",
    )
    readonly_fields = (
        "total_leads_matched",
        "created_at",
        "updated_at",
    )
