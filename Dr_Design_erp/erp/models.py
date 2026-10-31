from django.db import models

# Create your models here.
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager


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

    # Custom Manager
    objects = CustomUserManager()

    # Login with email
    USERNAME_FIELD = "email"

    REQUIRED_FIELDS = []

    def __str__(self):
        return f"{self.email} ({self.get_role_display()})"