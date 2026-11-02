from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model
from django.utils import timezone

from rest_framework import generics
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError

from erp.models import EmailOTP, Lead
from erp.utils import (
    send_otp_email,
    generate_password_reset_token,
    verify_password_reset_token,
)
from erp.serializers import (
    SignupSerializer,
    VerifyOTPSerializer,
    ResendOTPSerializer,
    ForgotPasswordRequestSerializer,
    ForgotPasswordVerifyOTPSerializer,
    ResetPasswordSerializer,
    LeadSerializer,
)

User = get_user_model()


# Home View
def home(request):
    if request.user.is_authenticated:
        return redirect("dashboard")
    return render(request, "login.html")


# Dashboard View
@login_required(login_url="login")
def dashboard_view(request):
    user = request.user
    full_name = f"{user.first_name} {user.last_name}".strip()
    if not full_name:
        full_name = user.email.split("@")[0].capitalize()

    role_disp = (
        user.get_role_display()
        if hasattr(user, "get_role_display")
        else getattr(user, "role", "Staff")
    )

    context = {
        "full_name": full_name,
        "username": getattr(user, "username", None) or user.email,
        "email": user.email,
        "role_display": role_disp,
        "employee_id": f"DR-EMP-{user.id:04d}",
        "phone": getattr(user, "phone", "Not Provided"),
        "email_verified": getattr(user, "is_email_verified", True),
        "last_login": user.last_login,
    }
    return render(request, "dashboard.html", context)


# Signup API
class SignupAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = SignupSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.save()

            # Generate OTP & send via SMTP
            otp_record = EmailOTP.generate_otp(email=user.email, purpose="SIGNUP")
            email_sent, error = send_otp_email(user.email, otp_record.otp, purpose="SIGNUP")

            if not email_sent:
                return Response({
                    "success": True,
                    "warning": "Account created, but OTP email could not be sent. Please use resend OTP.",
                    "error_detail": error,
                    "message": "Account created. Please request a new OTP if email was not received.",
                    "data": {
                        "id": user.id,
                        "email": user.email,
                        "role": user.role,
                        "is_active": user.is_active,
                        "is_email_verified": getattr(user, "is_email_verified", False),
                    }
                }, status=status.HTTP_201_CREATED)

            return Response({
                "success": True,
                "message": "Account created successfully. An OTP has been sent to your email for verification.",
                "data": {
                    "id": user.id,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "email": user.email,
                    "role": user.role,
                    "is_active": user.is_active,
                    "is_email_verified": getattr(user, "is_email_verified", False),
                }
            }, status=status.HTTP_201_CREATED)

        return Response({
            "success": False,
            "errors": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


# Verify OTP API (Signup)
class VerifyOTPAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                "success": False,
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"].strip().lower()
        otp = serializer.validated_data["otp"].strip()

        # Find the latest OTP record for this email (SIGNUP)
        otp_record = EmailOTP.objects.filter(email=email, purpose="SIGNUP").first()

        if not otp_record:
            return Response({
                "success": False,
                "message": "No OTP found for this email. Please sign up or request an OTP."
            }, status=status.HTTP_400_BAD_REQUEST)

        if otp_record.is_verified:
            return Response({
                "success": False,
                "message": "This OTP has already been verified."
            }, status=status.HTTP_400_BAD_REQUEST)

        if timezone.now() > otp_record.expires_at:
            return Response({
                "success": False,
                "message": "OTP has expired. Please request a new OTP."
            }, status=status.HTTP_400_BAD_REQUEST)

        if otp_record.otp != otp:
            return Response({
                "success": False,
                "message": "Invalid OTP. Please enter the correct 6-digit code."
            }, status=status.HTTP_400_BAD_REQUEST)

        # Mark OTP as verified
        otp_record.is_verified = True
        otp_record.save(update_fields=["is_verified"])

        # Activate user account
        try:
            user = User.objects.get(email=email)
            user.is_active = True
            user.is_email_verified = True
            user.save(update_fields=["is_active", "is_email_verified"])
        except User.DoesNotExist:
            return Response({
                "success": False,
                "message": "User account associated with this email not found."
            }, status=status.HTTP_404_NOT_FOUND)

        # Issue JWT tokens for authenticated session
        refresh = RefreshToken.for_user(user)

        return Response({
            "success": True,
            "message": "Email verified successfully! Your account is now active.",
            "data": {
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "user": {
                    "id": user.id,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "email": user.email,
                    "role": user.role,
                    "is_active": user.is_active,
                    "is_email_verified": user.is_email_verified,
                }
            }
        }, status=status.HTTP_200_OK)


# Resend OTP API (Signup)
class ResendOTPAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ResendOTPSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                "success": False,
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"].strip().lower()

        user = User.objects.filter(email=email).first()
        if not user:
            return Response({
                "success": False,
                "message": "No account found with this email."
            }, status=status.HTTP_404_NOT_FOUND)

        if user.is_active and getattr(user, "is_email_verified", False):
            return Response({
                "success": False,
                "message": "This account is already verified. You can log in directly."
            }, status=status.HTTP_400_BAD_REQUEST)

        # Generate fresh OTP and send via SMTP
        otp_record = EmailOTP.generate_otp(email=email, purpose="SIGNUP")
        email_sent, error = send_otp_email(email, otp_record.otp, purpose="SIGNUP")

        if not email_sent:
            return Response({
                "success": False,
                "message": "Failed to send OTP email. Please try again later.",
                "error_detail": error
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({
            "success": True,
            "message": "A new OTP has been sent to your email.",
            "data": {
                "email": email
            }
        }, status=status.HTTP_200_OK)


# --- Forgot Password API Views ---

# 1. Request Password Reset OTP
class ForgotPasswordRequestAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ForgotPasswordRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                "success": False,
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"]

        # Generate OTP specifically for password reset
        otp_record = EmailOTP.generate_otp(email=email, purpose="FORGOT_PASSWORD")
        email_sent, error = send_otp_email(email, otp_record.otp, purpose="FORGOT_PASSWORD")

        if not email_sent:
            return Response({
                "success": False,
                "message": "Failed to send password reset OTP email. Please try again.",
                "error_detail": error,
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({
            "success": True,
            "message": "Password reset OTP has been sent to your email.",
            "data": {
                "email": email
            }
        }, status=status.HTTP_200_OK)


# 2. Verify Password Reset OTP
class ForgotPasswordVerifyOTPAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ForgotPasswordVerifyOTPSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                "success": False,
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"].strip().lower()
        otp = serializer.validated_data["otp"].strip()

        # Find latest unverified OTP for password reset
        otp_record = EmailOTP.objects.filter(
            email=email,
            purpose="FORGOT_PASSWORD"
        ).first()

        if not otp_record:
            return Response({
                "success": False,
                "message": "No password reset OTP requested for this email. Please request an OTP first."
            }, status=status.HTTP_400_BAD_REQUEST)

        if otp_record.is_verified:
            return Response({
                "success": False,
                "message": "This OTP has already been verified."
            }, status=status.HTTP_400_BAD_REQUEST)

        if timezone.now() > otp_record.expires_at:
            return Response({
                "success": False,
                "message": "OTP has expired. Please request a new OTP."
            }, status=status.HTTP_400_BAD_REQUEST)

        if otp_record.otp != otp:
            return Response({
                "success": False,
                "message": "Invalid OTP code. Please enter the correct 6-digit code."
            }, status=status.HTTP_400_BAD_REQUEST)

        # Mark OTP as verified
        otp_record.is_verified = True
        otp_record.save(update_fields=["is_verified"])

        # Generate secure reset token
        reset_token = generate_password_reset_token(email, otp_record.id)

        return Response({
            "success": True,
            "message": "OTP verified successfully. You can now reset your password.",
            "data": {
                "email": email,
                "reset_token": reset_token
            }
        }, status=status.HTTP_200_OK)


# 3. Set New Password
class ResetPasswordAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                "success": False,
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.validated_data["user"]
        new_password = serializer.validated_data["new_password"]

        # Set new password
        user.set_password(new_password)
        user.is_active = True
        user.is_email_verified = True
        user.save()

        return Response({
            "success": True,
            "message": "Password has been reset successfully. You can now log in with your new password.",
            "data": {
                "email": user.email
            }
        }, status=status.HTTP_200_OK)


# --- Lead Generation API Views ---

class LeadCreateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        List all leads (Admins see all, staff see leads created by them)
        """
        if getattr(request.user, "role", "") == "ADMIN" or request.user.is_superuser:
            leads = Lead.objects.all()
        else:
            leads = Lead.objects.filter(created_by=request.user)

        serializer = LeadSerializer(leads, many=True)
        return Response({
            "success": True,
            "count": leads.count(),
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def post(self, request):
        """
        Add a New Lead (POST)
        """
        serializer = LeadSerializer(data=request.data)
        if serializer.is_valid():
            lead = serializer.save(created_by=request.user)
            return Response({
                "success": True,
                "message": "Lead created successfully.",
                "data": LeadSerializer(lead).data
            }, status=status.HTTP_201_CREATED)

        return Response({
            "success": False,
            "errors": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


class LeadDetailAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, pk, user):
        try:
            if getattr(user, "role", "") == "ADMIN" or user.is_superuser:
                return Lead.objects.get(pk=pk)
            return Lead.objects.get(pk=pk, created_by=user)
        except Lead.DoesNotExist:
            return None

    def get(self, request, pk):
        lead = self.get_object(pk, request.user)
        if not lead:
            return Response({
                "success": False,
                "message": "Lead not found or permission denied."
            }, status=status.HTTP_404_NOT_FOUND)

        serializer = LeadSerializer(lead)
        return Response({
            "success": True,
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def put(self, request, pk):
        lead = self.get_object(pk, request.user)
        if not lead:
            return Response({
                "success": False,
                "message": "Lead not found or permission denied."
            }, status=status.HTTP_404_NOT_FOUND)

        serializer = LeadSerializer(lead, data=request.data, partial=True)
        if serializer.is_valid():
            updated_lead = serializer.save()
            return Response({
                "success": True,
                "message": "Lead updated successfully.",
                "data": LeadSerializer(updated_lead).data
            }, status=status.HTTP_200_OK)

        return Response({
            "success": False,
            "errors": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk):
        """
        Partial Update a Lead (PATCH)
        """
        return self.put(request, pk)

    def delete(self, request, pk):
        """
        Delete a Lead (DELETE)
        """
        lead = self.get_object(pk, request.user)
        if not lead:
            return Response({
                "success": False,
                "message": "Lead not found or permission denied."
            }, status=status.HTTP_404_NOT_FOUND)

        lead_id = lead.lead_id
        client_name = lead.client_full_name
        lead.delete()

        return Response({
            "success": True,
            "message": f"Lead {lead_id} ({client_name}) deleted successfully.",
            "data": {
                "id": pk,
                "lead_id": lead_id,
            }
        }, status=status.HTTP_200_OK)

    def post(self, request, pk):
        """
        Support POST to /delete/ or /update/ endpoints for HTML/standard forms
        """
        if "delete" in request.path:
            return self.delete(request, pk)
        return self.put(request, pk)


# Login API View (Handles both Web UI & API requests)
class LoginAPIView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        if request.user.is_authenticated:
            return redirect("dashboard")
        return render(request, "login.html")

    def post(self, request):
        email = request.data.get("email", "").strip().lower()
        password = request.data.get("password")

        # Check if account exists but unverified
        unverified_user = User.objects.filter(email=email).first()
        if unverified_user and unverified_user.check_password(password) and not unverified_user.is_active:
            if request.content_type == "application/json" or "application/json" in request.headers.get("Accept", ""):
                return Response({
                    "success": False,
                    "message": "Account is not verified. Please verify your email using the OTP sent to your email.",
                    "is_verified": False,
                    "email": unverified_user.email
                }, status=status.HTTP_403_FORBIDDEN)

            return render(
                request,
                "login.html",
                {
                    "error_message": "Account is not verified. Please verify the OTP sent to your email."
                },
            )

        # Authenticate user
        user = authenticate(request, email=email, password=password)
        if user is None:
            user = authenticate(request, username=email, password=password)

        if user is not None:
            login(request, user)  # Log the user in

            # If request is JSON / API, return JWT token response
            if request.content_type == "application/json" or "application/json" in request.headers.get("Accept", ""):
                refresh = RefreshToken.for_user(user)
                return Response({
                    "success": True,
                    "message": "Login successful.",
                    "data": {
                        "refresh": str(refresh),
                        "access": str(refresh.access_token),
                        "user": {
                            "id": user.id,
                            "first_name": user.first_name,
                            "last_name": user.last_name,
                            "email": user.email,
                            "role": user.role,
                            "is_email_verified": getattr(user, "is_email_verified", True),
                        }
                    }
                }, status=status.HTTP_200_OK)

            # Web browser form submission -> redirect to dashboard
            return redirect("dashboard")

        # Invalid credentials:
        if request.content_type == "application/json" or "application/json" in request.headers.get("Accept", ""):
            return Response({
                "success": False,
                "message": "Invalid email or password."
            }, status=status.HTTP_401_UNAUTHORIZED)

        return render(
            request,
            "login.html",
            {
                "error_message": "Invalid credentials. Please verify your email & password."
            },
        )


# Logout API View (Handles both Web UI & API requests)
class LogoutAPIView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        logout(request)
        return redirect("login")

    def post(self, request):
        logout(request)
        return Response({
            "success": True,
            "message": "Logout successful."
        }, status=status.HTTP_200_OK)
