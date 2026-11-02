from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.utils import timezone

from erp.models import EmailOTP, Lead
from erp.utils import verify_password_reset_token

User = get_user_model()


class SignupSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()

    password = serializers.CharField(
        write_only=True,
        validators=[validate_password]
    )

    confirm_password = serializers.CharField(
        write_only=True
    )

    role = serializers.ChoiceField(
        choices=[
            ("LEAD_GEN", "Lead Generation"),
            ("INSIDE_SALES", "Inside Sales"),
            ("CRM", "CRM"),
            ("TECH", "Tech"),
            ("ACCOUNTS", "Accounts"),
        ]
    )

    class Meta:
        model = User
        fields = [
            "id",
            "first_name",
            "last_name",
            "email",
            "password",
            "confirm_password",
            "role",
        ]
        read_only_fields = ["id"]

    def validate(self, data):
        if data["password"] != data["confirm_password"]:
            raise serializers.ValidationError({
                "confirm_password": "Passwords do not match."
            })

        email = data.get("email", "").strip().lower()
        existing_user = User.objects.filter(email=email).first()
        if existing_user and existing_user.is_active:
            raise serializers.ValidationError({
                "email": "An account with this email already exists. Please log in."
            })

        return data

    def create(self, validated_data):
        validated_data.pop("confirm_password")
        email = validated_data.pop("email").strip().lower()
        password = validated_data.pop("password")

        # If unverified account already exists, update details & password
        existing_user = User.objects.filter(email=email, is_active=False).first()
        if existing_user:
            for attr, value in validated_data.items():
                setattr(existing_user, attr, value)
            existing_user.set_password(password)
            existing_user.is_active = False
            existing_user.is_email_verified = False
            existing_user.save()
            return existing_user

        # Create new inactive user pending OTP verification
        user = User.objects.create_user(
            email=email,
            password=password,
            is_active=False,
            is_email_verified=False,
            **validated_data
        )
        return user


class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(
        max_length=6,
        min_length=6,
        help_text="6-digit OTP code"
    )

    def validate_otp(self, value):
        value = value.strip()
        if not value.isdigit() or len(value) != 6:
            raise serializers.ValidationError("OTP must be a 6-digit numeric code.")
        return value


class ResendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()


# --- Forgot Password Serializers ---

class ForgotPasswordRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        email = value.strip().lower()
        if not User.objects.filter(email=email).exists():
            raise serializers.ValidationError("No account found with this email address.")
        return email


class ForgotPasswordVerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(
        max_length=6,
        min_length=6,
        help_text="6-digit OTP code"
    )

    def validate_otp(self, value):
        value = value.strip()
        if not value.isdigit() or len(value) != 6:
            raise serializers.ValidationError("OTP must be a 6-digit numeric code.")
        return value


class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    reset_token = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="Reset token received from /api/forgot-password/verify-otp/"
    )
    otp = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=6,
        min_length=6,
        help_text="Or direct 6-digit OTP code"
    )
    new_password = serializers.CharField(
        write_only=True,
        validators=[validate_password]
    )
    confirm_password = serializers.CharField(
        write_only=True
    )

    def validate(self, data):
        if data["new_password"] != data["confirm_password"]:
            raise serializers.ValidationError({
                "confirm_password": "Passwords do not match."
            })

        email = data.get("email", "").strip().lower()
        reset_token = data.get("reset_token", "").strip()
        otp = data.get("otp", "").strip()

        if not reset_token and not otp:
            raise serializers.ValidationError(
                "Either 'reset_token' (from OTP verification) or 'otp' is required to reset password."
            )

        user = User.objects.filter(email=email).first()
        if not user:
            raise serializers.ValidationError({
                "email": "No account found with this email address."
            })

        # Validate token or direct OTP
        if reset_token:
            valid, err_msg = verify_password_reset_token(email, reset_token)
            if not valid:
                raise serializers.ValidationError({
                    "reset_token": err_msg
                })
        elif otp:
            otp_record = EmailOTP.objects.filter(
                email=email,
                purpose="FORGOT_PASSWORD"
            ).first()

            if not otp_record:
                raise serializers.ValidationError({
                    "otp": "No password reset OTP requested for this email."
                })
            if otp_record.is_verified:
                raise serializers.ValidationError({
                    "otp": "This OTP has already been used. Please request a new OTP."
                })
            if timezone.now() > otp_record.expires_at:
                raise serializers.ValidationError({
                    "otp": "OTP has expired. Please request a new OTP."
                })
            if otp_record.otp != otp:
                raise serializers.ValidationError({
                    "otp": "Invalid OTP code."
                })

            otp_record.is_verified = True
            otp_record.save(update_fields=["is_verified"])

        data["user"] = user
        return data


# --- Lead Serializers (Lead Generation) ---

class LeadSerializer(serializers.ModelSerializer):
    lead_id = serializers.ReadOnlyField()
    created_by_email = serializers.ReadOnlyField(source="created_by.email")
    created_by_name = serializers.SerializerMethodField()

    client_website_address = serializers.CharField(
        required=False,
        allow_blank=True,
        default="",
        help_text="Optional website address e.g. https://client.com"
    )

    class Meta:
        model = Lead
        fields = [
            "id",
            "lead_id",
            "client_full_name",
            "client_email",
            "client_company_name",
            "client_website_address",
            "client_is",
            "country_name",
            "client_full_address",
            "client_contact_number",
            "lead_type",
            "project_category",
            "requirement_description",
            "status",
            "next_follow_up",
            "lead_generated_from",
            "created_by",
            "created_by_email",
            "created_by_name",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "lead_id",
            "created_by",
            "created_by_email",
            "created_by_name",
            "created_at",
            "updated_at",
        ]

    def get_created_by_name(self, obj):
        if obj.created_by:
            full_name = f"{obj.created_by.first_name} {obj.created_by.last_name}".strip()
            return full_name or obj.created_by.email
        return None

    def validate_requirement_description(self, value):
        val = value.strip() if value else ""
        if len(val) < 50:
            raise serializers.ValidationError(
                f"Requirement description must be at least 50 characters. (Current length: {len(val)})"
            )
        return val

    def to_internal_value(self, data):
        # Support flexible aliases from various frontend payloads
        mutable_data = data.copy() if hasattr(data, "copy") else dict(data)

        if "client_name" in mutable_data and "client_full_name" not in mutable_data:
            mutable_data["client_full_name"] = mutable_data["client_name"]
        if "client_email_id" in mutable_data and "client_email" not in mutable_data:
            mutable_data["client_email"] = mutable_data["client_email_id"]
        if "client_website" in mutable_data and "client_website_address" not in mutable_data:
            mutable_data["client_website_address"] = mutable_data["client_website"]
        if "client_address" in mutable_data and "client_full_address" not in mutable_data:
            mutable_data["client_full_address"] = mutable_data["client_address"]
        if "client_contact" in mutable_data and "client_contact_number" not in mutable_data:
            mutable_data["client_contact_number"] = mutable_data["client_contact"]
        if "lead_source" in mutable_data and "lead_generated_from" not in mutable_data:
            mutable_data["lead_generated_from"] = mutable_data["lead_source"]

        return super().to_internal_value(mutable_data)
