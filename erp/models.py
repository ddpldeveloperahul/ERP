import random
from datetime import timedelta
from django.db import models
from django.db.models import Q
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils import timezone


# 1. Custom User Manager
class CustomUserManager(BaseUserManager):

    def create_user(self, email, password=None, **extra_fields):

        if not email:
            raise ValueError("Email address is required")

        email = self.normalize_email(email)

        user = self.model(
            email=email,
            **extra_fields
        )

        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_superuser(self, email, password=None, **extra_fields):

        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("role", "ADMIN")
        extra_fields.setdefault("is_email_verified", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True")

        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True")

        return self.create_user(
            email=email,
            password=password,
            **extra_fields
        )


# 2. Custom User Model
class User(AbstractUser):

    # ERP Roles
    ROLE_CHOICES = [
        ("ADMIN", "Admin"),
        ("LEAD_GEN", "Lead Generation"),
        ("INSIDE_SALES", "Inside Sales"),
        ("CRM", "CRM"),
        ("TECH", "Tech"),
        ("ACCOUNTS", "Accounts"),
    ]

    # Remove default username
    username = None

    # Email as unique login identifier
    email = models.EmailField(
        unique=True,
        max_length=255
    )

    # User Role
    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES
    )

    # Email verification status
    is_email_verified = models.BooleanField(
        default=False
    )

    # Custom Manager
    objects = CustomUserManager()

    # Login with email
    USERNAME_FIELD = "email"

    REQUIRED_FIELDS = []

    def __str__(self):
        return f"{self.email} ({self.get_role_display()})"


# 3. OTP Verification Model
class EmailOTP(models.Model):
    PURPOSE_CHOICES = [
        ("SIGNUP", "Signup Verification"),
        ("FORGOT_PASSWORD", "Forgot Password"),
    ]

    email = models.EmailField(
        max_length=255,
        db_index=True
    )
    otp = models.CharField(
        max_length=6
    )
    purpose = models.CharField(
        max_length=20,
        choices=PURPOSE_CHOICES,
        default="SIGNUP"
    )
    created_at = models.DateTimeField(
        auto_now_add=True
    )
    expires_at = models.DateTimeField()
    is_verified = models.BooleanField(
        default=False
    )

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Email OTP"
        verbose_name_plural = "Email OTPs"

    def __str__(self):
        status = "Verified" if self.is_verified else "Pending"
        return f"{self.email} [{self.purpose}] - {self.otp} ({status})"

    def is_valid(self):
        return (not self.is_verified) and (timezone.now() <= self.expires_at)

    @classmethod
    def generate_otp(cls, email, purpose="SIGNUP", expiry_minutes=10):
        otp = f"{random.randint(100000, 999999)}"
        expires_at = timezone.now() + timedelta(minutes=expiry_minutes)

        otp_record = cls.objects.create(
            email=email,
            otp=otp,
            purpose=purpose,
            expires_at=expires_at,
        )
        return otp_record


# 4. Lead Model (Lead Generation)
class Lead(models.Model):
    CLIENT_IS_CHOICES = [
        ("Domestic", "Domestic"),
        ("International", "International"),
    ]

    PROJECT_CATEGORY_CHOICES = [
        ("Website Design & Development", "Website Design & Development"),
        ("E-commerce Website", "E-commerce Website"),
        ("Mobile App Development", "Mobile App Development"),
        ("Custom Software / ERP / CRM", "Custom Software / ERP / CRM"),
        ("SEO", "SEO"),
        ("Social Media Marketing", "Social Media Marketing"),
        ("Google / Meta Ads", "Google / Meta Ads"),
        ("Graphic Designing", "Graphic Designing"),
        ("Video Editing", "Video Editing"),
        ("UI/UX Design", "UI/UX Design"),
        ("Website Maintenance", "Website Maintenance"),
        ("Domain & Hosting", "Domain & Hosting"),
    ]

    NEXT_FOLLOW_UP_CHOICES = [
        ("Yes", "Yes"),
        ("No", "No"),
    ]

    LEAD_SOURCE_CHOICES = [
        ("Calling", "Calling"),
        ("WhatsApp", "WhatsApp"),
        ("Email", "Email"),
        ("Website Enquiry", "Website Enquiry"),
        ("Social Media", "Social Media"),
        ("Referral", "Referral"),
        ("Walk-in", "Walk-in"),
        ("Freelance Portal", "Freelance Portal"),
        ("Google Ads", "Google Ads"),
    ]

    STATUS_CHOICES = [
        ("Open", "Open"),
        ("In Progress", "In Progress"),
        ("Follow Up", "Follow Up"),
        ("Converted", "Converted"),
        ("Closed", "Closed"),
        ("Lost", "Lost"),
    ]

    LEAD_TYPE_CHOICES = [
        ("Inbound", "Inbound"),
        ("Outbound", "Outbound"),
        ("Hot", "Hot"),
        ("Warm", "Warm"),
        ("Cold", "Cold"),
    ]

    client_full_name = models.CharField(
        max_length=255,
        db_column="name",
        verbose_name="Client Full Name"
    )
    client_email = models.EmailField(
        max_length=255,
        db_column="email",
        verbose_name="Client Email ID"
    )
    client_company_name = models.CharField(
        max_length=255,
        db_column="company",
        verbose_name="Client Company Name"
    )
    client_website_address = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        default="",
        db_column="website",
        verbose_name="Client Website Address"
    )
    client_is = models.CharField(
        max_length=50,
        choices=CLIENT_IS_CHOICES,
        db_column="prospect_is",
        verbose_name="Client Is (Domestic / International)"
    )
    country_name = models.CharField(
        max_length=100,
        db_column="country",
        verbose_name="Country Name"
    )
    client_full_address = models.TextField(
        db_column="address",
        verbose_name="Client Full Address"
    )
    client_contact_number = models.CharField(
        max_length=50,
        db_column="phone",
        verbose_name="Client Contact Number"
    )
    lead_type = models.CharField(
        max_length=50,
        choices=LEAD_TYPE_CHOICES,
        db_column="lead_type",
        verbose_name="Lead Type"
    )
    project_category = models.CharField(
        max_length=150,
        choices=PROJECT_CATEGORY_CHOICES,
        db_column="category",
        verbose_name="Project Category"
    )
    requirement_description = models.TextField(
        db_column="requirement",
        verbose_name="Requirement Description"
    )
    status = models.CharField(
        max_length=50,
        choices=STATUS_CHOICES,
        default="Open",
        db_column="status",
        verbose_name="Status"
    )
    next_follow_up = models.CharField(
        max_length=10,
        choices=NEXT_FOLLOW_UP_CHOICES,
        default="Yes",
        db_column="next_follow_up",
        verbose_name="Next Follow Up"
    )
    lead_generated_from = models.CharField(
        max_length=100,
        choices=LEAD_SOURCE_CHOICES,
        default="Calling",
        db_column="source",
        verbose_name="Lead generated from?"
    )

    created_by = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="leads",
        db_column="created_by_id",
        verbose_name="Created By (User)"
    )
    created_at = models.DateTimeField(
        auto_now_add=True
    )
    updated_at = models.DateTimeField(
        auto_now=True
    )

    class Meta:
        db_table = "erp_lead"
        ordering = ["-created_at"]
        verbose_name = "Lead"
        verbose_name_plural = "Leads"

    @property
    def lead_id(self):
        return f"DR-LEAD-{self.id:04d}" if self.id else ""

    def __str__(self):
        return f"{self.lead_id} - {self.client_full_name} ({self.client_company_name})"



# 5. Schedule Callback Model
class ScheduleCallback(models.Model):
    CALLBACK_TYPE_CHOICES = [
        ("Public", "Public"),
        ("Private", "Private"),
    ]

    STATUS_CHOICES = [
        ("Pending", "Pending"),
        ("Completed", "Completed"),
        ("Cancelled", "Cancelled"),
    ]

    lead = models.ForeignKey(
        Lead,
        on_delete=models.CASCADE,
        related_name="callbacks",
        verbose_name="Associated Lead"
    )
    phone = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        verbose_name="Phone Number"
    )
    date_time = models.DateTimeField(
        verbose_name="Callback Date & Time"
    )
    type = models.CharField(
        max_length=20,
        choices=CALLBACK_TYPE_CHOICES,
        default="Public",
        verbose_name="Callback Type"
    )
    notes = models.TextField(
        blank=True,
        null=True,
        default="",
        verbose_name="Notes"
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="Pending",
        verbose_name="Callback Status"
    )

    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="scheduled_callbacks",
        verbose_name="Created By"
    )
    created_at = models.DateTimeField(
        auto_now_add=True
    )
    updated_at = models.DateTimeField(
        auto_now=True
    )

    class Meta:
        ordering = ["date_time"]
        verbose_name = "Schedule Callback"
        verbose_name_plural = "Schedule Callbacks"

    def __str__(self):
        lead_ref = self.lead.lead_id if hasattr(self.lead, "lead_id") else f"Lead #{self.lead_id}"
        return f"{lead_ref} - {self.date_time.strftime('%Y-%m-%d %H:%M')} ({self.type})"


# 6. Email Campaign Model
class EmailCampaign(models.Model):
    LEAD_TYPE_CHOICES = [
        ("Any", "Any"),
        ("Hot", "Hot"),
        ("Warm", "Warm"),
        ("Cold", "Cold"),
    ]

    CATEGORY_CHOICES = [
        ("Any", "Any"),
        ("Website Design & Development", "Website Design & Development"),
        ("E-commerce Website", "E-commerce Website"),
        ("Mobile App Development", "Mobile App Development"),
        ("Custom Software / ERP / CRM", "Custom Software / ERP / CRM"),
        ("SEO", "SEO"),
        ("Social Media Marketing", "Social Media Marketing"),
        ("Google / Meta Ads", "Google / Meta Ads"),
        ("Graphic Designing", "Graphic Designing"),
        ("Video Editing", "Video Editing"),
        ("UI/UX Design", "UI/UX Design"),
        ("Website Maintenance", "Website Maintenance"),
        ("Domain & Hosting", "Domain & Hosting"),
    ]

    COUNTRY_CHOICES = [
        ("Any", "Any"),
        ("India", "India"),
        ("United States", "United States"),
        ("United Kingdom", "United Kingdom"),
        ("United Arab Emirates", "United Arab Emirates"),
        ("Canada", "Canada"),
        ("Australia", "Australia"),
        ("Singapore", "Singapore"),
        ("Saudi Arabia", "Saudi Arabia"),
        ("Qatar", "Qatar"),
        ("Germany", "Germany"),
        ("Nepal", "Nepal"),
        ("Other", "Other"),
    ]

    CLIENT_IS_CHOICES = [
        ("Any", "Any"),
        ("Domestic", "Domestic"),
        ("International", "International"),
    ]

    SALES_STATUS_CHOICES = [
        ("Any (except Lost/Closed)", "Any (except Lost/Closed)"),
        ("Open", "Open"),
        ("In Progress", "In Progress"),
        ("Follow Up", "Follow Up"),
        ("Converted", "Converted"),
        ("Lost", "Lost"),
        ("Closed", "Closed"),
    ]

    STATUS_CHOICES = [
        ("Draft", "Draft"),
        ("Scheduled", "Scheduled"),
        ("In Progress", "In Progress"),
        ("Completed", "Completed"),
        ("Cancelled", "Cancelled"),
    ]

    name = models.CharField(
        max_length=255,
        verbose_name="Campaign Name",
        help_text="e.g. Diwali offer — UK design leads"
    )

    # Audience Filters
    lead_type = models.CharField(
        max_length=50,
        choices=LEAD_TYPE_CHOICES,
        default="Any",
        blank=True,
        verbose_name="Audience Lead Type"
    )
    category = models.CharField(
        max_length=150,
        choices=CATEGORY_CHOICES,
        default="Any",
        blank=True,
        verbose_name="Audience Category"
    )
    country = models.CharField(
        max_length=100,
        choices=COUNTRY_CHOICES,
        default="Any",
        blank=True,
        verbose_name="Audience Country"
    )
    client_is = models.CharField(
        max_length=50,
        choices=CLIENT_IS_CHOICES,
        default="Any",
        blank=True,
        verbose_name="Audience Client Is"
    )
    sales_status = models.CharField(
        max_length=100,
        choices=SALES_STATUS_CHOICES,
        default="Any (except Lost/Closed)",
        blank=True,
        verbose_name="Audience Sales Status"
    )
    generated_from_date = models.DateField(
        null=True,
        blank=True,
        verbose_name="Generated Between (Start Date)"
    )
    generated_to_date = models.DateField(
        null=True,
        blank=True,
        verbose_name="Generated Between (End Date)"
    )

    # Email Content
    subject = models.CharField(
        max_length=255,
        verbose_name="Email Subject"
    )
    message = models.TextField(
        verbose_name="Message Template",
        help_text="Use {name} and {company} placeholders"
    )

    # Campaign Status & Metadata
    status = models.CharField(
        max_length=30,
        choices=STATUS_CHOICES,
        default="Draft",
        verbose_name="Campaign Status"
    )
    total_leads_matched = models.IntegerField(
        default=0,
        verbose_name="Matched Leads Count"
    )

    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="campaigns",
        verbose_name="Created By"
    )
    created_at = models.DateTimeField(
        auto_now_add=True
    )
    updated_at = models.DateTimeField(
        auto_now=True
    )

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Email Campaign"
        verbose_name_plural = "Email Campaigns"

    @property
    def campaign_id(self):
        return f"CAMP-{self.id:04d}" if self.id else ""

    @property
    def campaign_name(self):
        return self.name

    @campaign_name.setter
    def campaign_name(self, value):
        self.name = value

    @property
    def matching_leads_count(self):
        return self.total_leads_matched or self.get_matching_leads_queryset().count()

    @property
    def audience_summary(self):
        filters = []
        if self.country and self.country != "Any":
            filters.append(f"country: {self.country}")
        if self.lead_type and self.lead_type != "Any":
            filters.append(f"lead type: {self.lead_type}")
        if self.category and self.category != "Any":
            filters.append(f"category: {self.category}")
        if self.client_is and self.client_is != "Any":
            filters.append(f"client is: {self.client_is}")
        if self.sales_status and self.sales_status not in ["Any", "Any (except Lost/Closed)"]:
            filters.append(f"status: {self.sales_status}")
        if self.generated_from_date or self.generated_to_date:
            from_str = self.generated_from_date.strftime("%d-%m-%Y") if self.generated_from_date else "start"
            to_str = self.generated_to_date.strftime("%d-%m-%Y") if self.generated_to_date else "today"
            filters.append(f"dates: {from_str} to {to_str}")

        if not filters:
            return "All my leads"
        return ", ".join(filters)

    def __str__(self):
        return f"{self.campaign_id} - {self.name} ({self.status})"

    def get_matching_leads_queryset(self, user=None):
        from erp.models import Lead
        eval_user = user or self.created_by
        if eval_user and (getattr(eval_user, "role", "") == "ADMIN" or eval_user.is_superuser):
            qs = Lead.objects.all()
        elif eval_user:
            qs = Lead.objects.filter(created_by=eval_user)
        else:
            qs = Lead.objects.all()

        # Only leads with valid email address
        qs = qs.exclude(client_email="").exclude(client_email__isnull=True)

        if self.lead_type and self.lead_type != "Any":
            qs = qs.filter(lead_type__iexact=self.lead_type.strip())

        if self.category and self.category != "Any":
            qs = qs.filter(project_category__icontains=self.category.strip())

        if self.country and self.country != "Any":
            qs = qs.filter(country_name__icontains=self.country.strip())

        if self.client_is and self.client_is != "Any":
            qs = qs.filter(client_is__iexact=self.client_is.strip())

        if self.sales_status:
            status_clean = self.sales_status.strip()
            if status_clean.lower() in ["any (except lost/closed)", "except lost/closed", "any_except_lost_closed"]:
                qs = qs.exclude(status__in=["Lost", "Closed"])
            elif status_clean.lower() == "follow up":
                qs = qs.filter(Q(status__iexact="Follow Up") | Q(next_follow_up__iexact="Yes"))
            elif status_clean.lower() != "any":
                qs = qs.filter(status__iexact=status_clean)

        if self.generated_from_date:
            qs = qs.filter(created_at__date__gte=self.generated_from_date)

        if self.generated_to_date:
            qs = qs.filter(created_at__date__lte=self.generated_to_date)

        return qs


# Convenience alias
Campaign = EmailCampaign
