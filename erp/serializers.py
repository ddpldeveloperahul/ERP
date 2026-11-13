from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.utils import timezone

from erp.models import EmailOTP, Lead, ScheduleCallback, EmailCampaign, Client, Project
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



# --- Schedule Callback Serializers ---

class ScheduleCallbackSerializer(serializers.ModelSerializer):
    lead_id = serializers.CharField(
        write_only=True,
        required=False,
        help_text="Lead code (e.g. 'DR-LEAD-0011') or numeric Lead ID (e.g. 11)"
    )
    lead_ref = serializers.SerializerMethodField(read_only=True)
    client_name = serializers.ReadOnlyField(source="lead.client_full_name")
    client_email = serializers.ReadOnlyField(source="lead.client_email")
    client_company = serializers.ReadOnlyField(source="lead.client_company_name")
    created_by_name = serializers.SerializerMethodField(read_only=True)

    date_time = serializers.DateTimeField(
        input_formats=[
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M",
            "%d-%m-%Y %H:%M",
            "%d-%m-%Y %H:%M:%S",
            "%d/%m/%Y %H:%M",
            "%d/%m/%Y %H:%M:%S",
        ],
        help_text="Format: 'YYYY-MM-DD HH:MM:SS' or 'DD-MM-YYYY HH:MM'"
    )

    class Meta:
        model = ScheduleCallback
        fields = [
            "id",
            "lead",
            "lead_id",
            "lead_ref",
            "client_name",
            "client_email",
            "client_company",
            "phone",
            "date_time",
            "type",
            "notes",
            "status",
            "created_by",
            "created_by_name",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "lead_ref",
            "client_name",
            "client_email",
            "client_company",
            "created_by",
            "created_by_name",
            "created_at",
            "updated_at",
        ]
        extra_kwargs = {
            "lead": {"required": False},
        }

    def get_lead_ref(self, obj):
        return obj.lead.lead_id if obj.lead else None

    def get_created_by_name(self, obj):
        if obj.created_by:
            full_name = f"{obj.created_by.first_name} {obj.created_by.last_name}".strip()
            return full_name or obj.created_by.email
        return None

    def validate(self, data):
        # Resolve lead from lead_id or lead field
        lead = data.get("lead")
        lead_id_input = data.pop("lead_id", None)

        if lead_id_input:
            lead_id_str = str(lead_id_input).strip()
            # If formatted like DR-LEAD-0011
            if lead_id_str.upper().startswith("DR-LEAD-"):
                num_str = lead_id_str.upper().replace("DR-LEAD-", "").lstrip("0")
                lead_pk = int(num_str) if (num_str and num_str.isdigit()) else 0
            elif lead_id_str.isdigit():
                lead_pk = int(lead_id_str)
            else:
                lead_pk = None

            if lead_pk is None:
                raise serializers.ValidationError({
                    "lead_id": f"Invalid lead_id format '{lead_id_input}'. Expected integer ID or 'DR-LEAD-XXXX'."
                })

            try:
                lead = Lead.objects.get(pk=lead_pk)
            except Lead.DoesNotExist:
                raise serializers.ValidationError({
                    "lead_id": f"No lead found with ID '{lead_id_input}'."
                })

            data["lead"] = lead

        if not data.get("lead") and not self.instance:
            raise serializers.ValidationError({"lead_id": "Lead ID is required to schedule a callback."})

        # Auto-populate phone from lead contact number if left blank
        if not data.get("phone"):
            resolved_lead = data.get("lead") or (self.instance.lead if self.instance else None)
            if resolved_lead and resolved_lead.client_contact_number:
                data["phone"] = resolved_lead.client_contact_number

        return data


# --- Email Campaign Serializer ---

class EmailCampaignSerializer(serializers.ModelSerializer):
    campaign_name = serializers.CharField(source="name", required=False)
    campaign_id = serializers.SerializerMethodField(read_only=True)
    created_by_name = serializers.SerializerMethodField(read_only=True)
    audience_summary = serializers.CharField(read_only=True)
    recipients_count = serializers.IntegerField(source="matching_leads_count", read_only=True)

    lead_type = serializers.ChoiceField(
        choices=EmailCampaign.LEAD_TYPE_CHOICES,
        default="Any",
        required=False
    )
    category = serializers.ChoiceField(
        choices=EmailCampaign.CATEGORY_CHOICES,
        default="Any",
        required=False
    )
    country = serializers.ChoiceField(
        choices=EmailCampaign.COUNTRY_CHOICES,
        default="Any",
        required=False
    )
    client_is = serializers.ChoiceField(
        choices=EmailCampaign.CLIENT_IS_CHOICES,
        default="Any",
        required=False
    )
    sales_status = serializers.ChoiceField(
        choices=EmailCampaign.SALES_STATUS_CHOICES,
        default="Any (except Lost/Closed)",
        required=False
    )

    generated_from_date = serializers.DateField(
        input_formats=["%Y-%m-%d", "%d-%m-%Y", "%d/%m/%Y"],
        required=False,
        allow_null=True
    )
    generated_to_date = serializers.DateField(
        input_formats=["%Y-%m-%d", "%d-%m-%Y", "%d/%m/%Y"],
        required=False,
        allow_null=True
    )

    class Meta:
        model = EmailCampaign
        fields = [
            "id",
            "campaign_id",
            "campaign_name",
            "lead_type",
            "category",
            "country",
            "client_is",
            "sales_status",
            "generated_from_date",
            "generated_to_date",
            "subject",
            "message",
            "status",
            "audience_summary",
            "recipients_count",
            "created_by_name",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "campaign_id",
            "audience_summary",
            "recipients_count",
            "created_by_name",
            "created_at",
            "updated_at",
        ]
        extra_kwargs = {
            "name": {"required": False},
        }

    def get_campaign_id(self, obj):
        return obj.campaign_id

    def get_created_by_name(self, obj):
        if obj.created_by:
            name = f"{obj.created_by.first_name} {obj.created_by.last_name}".strip()
            return name or obj.created_by.email
        return None

    def to_internal_value(self, data):
        mutable_data = data.copy() if hasattr(data, "copy") else dict(data)

        # Flexible alias for Campaign name
        if "campaign_name" in mutable_data and not mutable_data.get("name"):
            mutable_data["name"] = mutable_data["campaign_name"]

        # Flexible alias for Category
        if "project_category" in mutable_data and "category" not in mutable_data:
            mutable_data["category"] = mutable_data["project_category"]

        # Flexible alias for Country
        if "country_name" in mutable_data and "country" not in mutable_data:
            mutable_data["country"] = mutable_data["country_name"]

        # Flexible alias for Generated between dates
        if "generated_between_from" in mutable_data and "generated_from_date" not in mutable_data:
            mutable_data["generated_from_date"] = mutable_data["generated_between_from"]
        if "generated_between_to" in mutable_data and "generated_to_date" not in mutable_data:
            mutable_data["generated_to_date"] = mutable_data["generated_between_to"]
        if "start_date" in mutable_data and "generated_from_date" not in mutable_data:
            mutable_data["generated_from_date"] = mutable_data["start_date"]
        if "end_date" in mutable_data and "generated_to_date" not in mutable_data:
            mutable_data["generated_to_date"] = mutable_data["end_date"]

        # Handle empty date strings
        if mutable_data.get("generated_from_date") == "":
            mutable_data["generated_from_date"] = None
        if mutable_data.get("generated_to_date") == "":
            mutable_data["generated_to_date"] = None

        return super().to_internal_value(mutable_data)

    def validate(self, data):
        # Ensure at least name or campaign_name is provided on create
        name = data.get("name")
        if not name and not self.instance:
            raise serializers.ValidationError({
                "campaign_name": "Campaign name is required."
            })

        from_date = data.get("generated_from_date")
        to_date = data.get("generated_to_date")
        if from_date and to_date and from_date > to_date:
            raise serializers.ValidationError({
                "generated_between": "Start date cannot be after End date."
            })

        return data


# =========================================================
# Client Serializer
# =========================================================
class ClientSerializer(serializers.ModelSerializer):
    created_by_name = serializers.SerializerMethodField(read_only=True)
    display_label = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Client
        fields = [
            "id",
            "client_name",
            "company_name",
            "email",
            "phone",
            "client_is",
            "address",
            "website",
            "country_name",
            "created_by",
            "created_by_name",
            "display_label",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "created_by",
            "created_by_name",
            "display_label",
            "created_at",
            "updated_at",
        ]

    def get_created_by_name(self, obj):
        if obj.created_by:
            full = f"{obj.created_by.first_name} {obj.created_by.last_name}".strip()
            return full or obj.created_by.email
        return None

    def get_display_label(self, obj):
        comp = f" ({obj.company_name})" if obj.company_name else ""
        return f"{obj.client_name}{comp}".strip()

    def to_internal_value(self, data):
        mutable_data = data.copy() if hasattr(data, "copy") else dict(data)
        if "name" in mutable_data and "client_name" not in mutable_data:
            mutable_data["client_name"] = mutable_data["name"]
        if "company" in mutable_data and "company_name" not in mutable_data:
            mutable_data["company_name"] = mutable_data["company"]
        if "contact" in mutable_data and "phone" not in mutable_data:
            mutable_data["phone"] = mutable_data["contact"]
        return super().to_internal_value(mutable_data)


# =========================================================
# User Brief Serializer (Dynamic Team Members & Managers)
# =========================================================
class UserBriefSerializer(serializers.ModelSerializer):
    name = serializers.SerializerMethodField()
    display_label = serializers.SerializerMethodField()
    role_display = serializers.CharField(source="get_role_display", read_only=True)

    class Meta:
        model = User
        fields = [
            "id",
            "name",
            "email",
            "role",
            "role_display",
            "designation",
            "department",
            "display_label",
        ]

    def get_name(self, obj):
        full = f"{obj.first_name} {obj.last_name}".strip()
        return full or obj.first_name or obj.email.split("@")[0].capitalize()

    def get_display_label(self, obj):
        return getattr(obj, "display_title", self.get_name(obj))


# =========================================================
# Project Serializer (CRUD & Dynamic Options)
# =========================================================
class ProjectSerializer(serializers.ModelSerializer):
    project_id = serializers.CharField(read_only=True)
    po_number = serializers.CharField(read_only=True)
    display_client_name = serializers.CharField(read_only=True)
    created_by_name = serializers.SerializerMethodField(read_only=True)
    project_manager_name = serializers.SerializerMethodField(read_only=True)
    project_manager_detail = UserBriefSerializer(source="project_manager", read_only=True)
    team_members_detail = UserBriefSerializer(source="team_members", many=True, read_only=True)
    team_member_names = serializers.SerializerMethodField(read_only=True)
    client_detail = ClientSerializer(source="client", read_only=True)
    value_formatted = serializers.SerializerMethodField(read_only=True)

    # Input handling
    client = serializers.PrimaryKeyRelatedField(
        queryset=Client.objects.all(),
        required=False,
        allow_null=True
    )
    client_id = serializers.IntegerField(
        write_only=True,
        required=False,
        allow_null=True
    )
    client_name = serializers.CharField(
        required=False,
        allow_blank=True
    )
    start_date = serializers.DateField(
        required=False,
        allow_null=True,
        input_formats=["%Y-%m-%d", "%d-%m-%Y", "%d/%m/%Y"]
    )
    deadline = serializers.DateField(
        required=True,
        input_formats=["%Y-%m-%d", "%d-%m-%Y", "%d/%m/%Y"]
    )
    project_manager = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(),
        required=False,
        allow_null=True
    )
    project_manager_id = serializers.IntegerField(
        write_only=True,
        required=False,
        allow_null=True
    )
    team_members = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(),
        many=True,
        required=False
    )

    class Meta:
        model = Project
        fields = [
            "id",
            "project_id",
            "po_number",
            "project_name",
            "client",
            "client_id",
            "client_name",
            "display_client_name",
            "client_detail",
            "category",
            "value",
            "value_formatted",
            "start_date",
            "deadline",
            "project_manager",
            "project_manager_id",
            "project_manager_name",
            "project_manager_detail",
            "team_members",
            "team_members_detail",
            "team_member_names",
            "scope",
            "completion",
            "status",
            "created_by",
            "created_by_name",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "project_id",
            "po_number",
            "display_client_name",
            "client_detail",
            "value_formatted",
            "project_manager_name",
            "project_manager_detail",
            "team_members_detail",
            "team_member_names",
            "created_by",
            "created_by_name",
            "created_at",
            "updated_at",
        ]

    def get_created_by_name(self, obj):
        if obj.created_by:
            full = f"{obj.created_by.first_name} {obj.created_by.last_name}".strip()
            return full or obj.created_by.email
        return None

    def get_project_manager_name(self, obj):
        if obj.project_manager:
            return obj.project_manager.get_full_name() or obj.project_manager.email
        return None

    def get_team_member_names(self, obj):
        return [m.display_title for m in obj.team_members.all()]

    def get_value_formatted(self, obj):
        try:
            return f"₹{obj.value:,.2f}"
        except Exception:
            return f"₹{obj.value}"

    def to_internal_value(self, data):
        mutable_data = data.copy() if hasattr(data, "copy") else dict(data)

        # Value aliases
        if "value_excl_tax" in mutable_data and "value" not in mutable_data:
            mutable_data["value"] = mutable_data["value_excl_tax"]
        if "project_value" in mutable_data and "value" not in mutable_data:
            mutable_data["value"] = mutable_data["project_value"]

        # Scope aliases
        if "description" in mutable_data and "scope" not in mutable_data:
            mutable_data["scope"] = mutable_data["description"]

        # Project manager alias
        if "project_manager_id" in mutable_data and "project_manager" not in mutable_data:
            mutable_data["project_manager"] = mutable_data["project_manager_id"]

        # Client aliases
        if "client_id" in mutable_data and "client" not in mutable_data:
            mutable_data["client"] = mutable_data["client_id"]

        # Team members list / comma-separated string
        if "team_members" in mutable_data:
            raw_members = mutable_data["team_members"]
            if isinstance(raw_members, str):
                mutable_data["team_members"] = [
                    int(x.strip()) for x in raw_members.split(",") if x.strip().isdigit()
                ]

        # Handle empty date strings
        if mutable_data.get("start_date") == "":
            mutable_data["start_date"] = None
        if mutable_data.get("deadline") == "":
            mutable_data["deadline"] = None

        has_client = bool(
            mutable_data.get("client")
            or mutable_data.get("client_id")
            or (isinstance(mutable_data.get("client_name"), str) and mutable_data.get("client_name").strip())
        )

        try:
            ret = super().to_internal_value(mutable_data)
        except serializers.ValidationError as exc:
            detail = exc.detail
            if not self.instance and not has_client:
                if isinstance(detail, dict) and "client" not in detail:
                    detail["client"] = [serializers.ErrorDetail("Client is required. Please select or enter a client.", code="required")]
            raise serializers.ValidationError(detail)

        if not self.instance and not has_client and not ret.get("client") and not ret.get("client_name"):
            raise serializers.ValidationError({
                "client": "Client is required. Please select or enter a client."
            })

        return ret

    def validate(self, data):
        # Validate client presence
        client = data.get("client")
        client_name = data.get("client_name")

        # Auto-create or resolve client if string was provided
        if not client and client_name and client_name.strip():
            c, _ = Client.objects.get_or_create(
                client_name=client_name.strip(),
                defaults={"company_name": client_name.strip()}
            )
            data["client"] = c
            data["client_name"] = c.client_name

        if not data.get("client") and not data.get("client_name") and not self.instance:
            raise serializers.ValidationError({
                "client": "Client is required. Please select or enter a client."
            })

        # Project name is required
        project_name = data.get("project_name")
        if not project_name and not self.instance:
            raise serializers.ValidationError({
                "project_name": "Project name is required."
            })

        # Deadline is required
        deadline = data.get("deadline")
        if not deadline and not self.instance:
            raise serializers.ValidationError({
                "deadline": "Deadline date is required."
            })

        start_date = data.get("start_date")
        if start_date and deadline and start_date > deadline:
            raise serializers.ValidationError({
                "deadline": "Deadline cannot be earlier than start date."
            })

        return data

