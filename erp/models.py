import random
from datetime import timedelta
from django.db import models
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
