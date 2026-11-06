from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.db.models import Q, Case, When, Value, IntegerField, Count
import datetime
from datetime import timedelta

from rest_framework import generics
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError

from erp.models import EmailOTP, Lead, ScheduleCallback, EmailCampaign
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
    ScheduleCallbackSerializer,
    EmailCampaignSerializer,
)

User = get_user_model()


# Home View
def home(request):
    if request.user.is_authenticated:
        return redirect("dashboard")
    return render(request, "login.html")


# Dashboard View
@login_required(login_url="login")
def dashboard_view(request, active_tab="dashboard"):
    user = request.user
    full_name = f"{user.first_name} {user.last_name}".strip()
    if not full_name:
        full_name = user.email.split("@")[0].capitalize()

    first_name = user.first_name or full_name.split()[0]
    avatar_initial = first_name[0].upper() if first_name else "A"

    role_disp = (
        user.get_role_display()
        if hasattr(user, "get_role_display")
        else getattr(user, "role", "Staff")
    )

    # JWT Token for client-side API requests
    refresh = RefreshToken.for_user(user)
    access_token = str(refresh.access_token)

    # Active view tab (dashboard, leads_add, leads_manage, callbacks)
    tab = request.GET.get("tab") or active_tab or "dashboard"

    # Leads & Callbacks queryset
    is_admin = getattr(user, "role", "") == "ADMIN" or user.is_superuser
    if is_admin:
        all_leads = Lead.objects.all()
        all_callbacks = ScheduleCallback.objects.all()
    else:
        all_leads = Lead.objects.filter(created_by=user)
        all_callbacks = ScheduleCallback.objects.filter(
            Q(type="Public") | Q(created_by=user) | Q(lead__created_by=user)
        )

    now = timezone.now()
    today = now.date()

    total_leads_count = all_leads.count()
    today_leads_count = all_leads.filter(created_at__date=today).count()
    this_month_leads = all_leads.filter(created_at__year=now.year, created_at__month=now.month)
    this_month_leads_count = this_month_leads.count()

    worked_upon_count = all_leads.exclude(status__iexact="Open").count()
    converted_count = all_leads.filter(status__iexact="Converted").count()
    converted_pct = round((converted_count / total_leads_count * 100), 1) if total_leads_count > 0 else 0

    hot_count = all_leads.filter(lead_type__iexact="Hot").count()
    warm_count = all_leads.filter(lead_type__iexact="Warm").count()
    cold_count = all_leads.filter(lead_type__iexact="Cold").count()

    recent_leads = all_leads.order_by("-created_at")[:10]
    urgent_callbacks = all_callbacks.filter(status="Pending").order_by("date_time")[:10]
    callbacks_count = all_callbacks.count()

    # Executive monthly stats
    executives_summary = []
    if is_admin:
        exec_stats = this_month_leads.values("created_by__first_name", "created_by__last_name", "created_by__email").annotate(count=Count("id")).order_by("-count")[:5]
        for item in exec_stats:
            name = f"{item['created_by__first_name'] or ''} {item['created_by__last_name'] or ''}".strip() or item["created_by__email"]
            executives_summary.append({"name": name, "count": item["count"]})
    else:
        executives_summary.append({"name": full_name, "count": this_month_leads_count})

    context = {
        "full_name": full_name,
        "first_name": first_name,
        "avatar_initial": avatar_initial,
        "username": getattr(user, "username", None) or user.email,
        "email": user.email,
        "role_display": role_disp,
        "employee_id": f"DR-EMP-{user.id:04d}",
        "phone": getattr(user, "phone", "Not Provided"),
        "email_verified": getattr(user, "is_email_verified", True),
        "last_login": user.last_login,
        "access_token": access_token,
        "active_tab": tab,
        # Metrics
        "total_leads_count": total_leads_count,
        "today_leads_count": today_leads_count,
        "this_month_leads_count": this_month_leads_count,
        "target_leads_count": 100,
        "worked_upon_count": worked_upon_count,
        "converted_count": converted_count,
        "converted_pct": converted_pct,
        "hot_count": hot_count,
        "warm_count": warm_count,
        "cold_count": cold_count,
        "recent_leads": recent_leads,
        "urgent_callbacks": urgent_callbacks,
        "callbacks_count": callbacks_count,
        "executives_summary": executives_summary,
        "today_formatted": now.strftime("%a, %d %b, %Y"),
        "time_formatted": now.strftime("%I:%M %p"),
    }
    return render(request, "dashboard.html", context)


@login_required(login_url="login")
def leads_manage_web_view(request):
    if request.headers.get("Accept", "").startswith("application/json") or request.content_type == "application/json":
        return LeadCreateAPIView.as_view()(request)
    return dashboard_view(request, active_tab="leads_manage")


@login_required(login_url="login")
def leads_add_web_view(request):
    if request.headers.get("Accept", "").startswith("application/json") or request.content_type == "application/json":
        return LeadCreateAPIView.as_view()(request)
    return dashboard_view(request, active_tab="leads_add")


@login_required(login_url="login")
def callbacks_web_view(request, lead_id=None):
    if request.headers.get("Accept", "").startswith("application/json") or request.content_type == "application/json":
        return ScheduleCallbackListCreateAPIView.as_view()(request, lead_id=lead_id)
    return dashboard_view(request, active_tab="callbacks")


@login_required(login_url="login")
def campaigns_web_view(request):
    if request.headers.get("Accept", "").startswith("application/json") or request.content_type == "application/json":
        return EmailCampaignListCreateAPIView.as_view()(request)
    return dashboard_view(request, active_tab="campaigns")


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
        List & Search leads:
        - Multi-field tokenized Elastic-style search (?search= or ?q=) with relevance scoring
        - Attribute filters (?status=, ?lead_type=, ?project_category=, ?client_is=, ?country=, ?source=, ?next_follow_up=)
        - Date range filter (?date_from=, ?date_to=)
        - Ordering (?ordering=)
        - Pagination (?page= & ?page_size=)
        """
        if getattr(request.user, "role", "") == "ADMIN" or request.user.is_superuser:
            leads = Lead.objects.all()
        else:
            leads = Lead.objects.filter(created_by=request.user)

        generated_by_param = request.query_params.get("generated_by")
        if generated_by_param and generated_by_param.lower() in ["me", "my"]:
            leads = leads.filter(created_by=request.user)

        # 1. Multi-Field Elastic Search (?search= or ?q=)
        search_query = request.query_params.get("search") or request.query_params.get("q")
        if search_query:
            search_query = search_query.strip()
            # Tokenize into words to match across multiple fields
            tokens = search_query.split()
            for token in tokens:
                token_q = (
                    Q(client_full_name__icontains=token)
                    | Q(client_email__icontains=token)
                    | Q(client_company_name__icontains=token)
                    | Q(client_website_address__icontains=token)
                    | Q(client_contact_number__icontains=token)
                    | Q(country_name__icontains=token)
                    | Q(client_full_address__icontains=token)
                    | Q(lead_type__icontains=token)
                    | Q(project_category__icontains=token)
                    | Q(requirement_description__icontains=token)
                    | Q(status__icontains=token)
                    | Q(next_follow_up__icontains=token)
                    | Q(lead_generated_from__icontains=token)
                    | Q(client_is__icontains=token)
                )

                # Check if token matches numeric ID or DR-LEAD-XXXX format
                if token.isdigit():
                    token_q |= Q(id=int(token))
                elif token.upper().startswith("DR-LEAD-"):
                    num_str = token.upper().replace("DR-LEAD-", "").lstrip("0")
                    if num_str.isdigit():
                        token_q |= Q(id=int(num_str))

                leads = leads.filter(token_q)

            # Elastic-style Relevance Ranking (Exact Name > Company > Partial Matches)
            leads = leads.annotate(
                relevance_score=Case(
                    When(client_full_name__iexact=search_query, then=Value(100)),
                    When(client_company_name__iexact=search_query, then=Value(90)),
                    When(client_full_name__icontains=search_query, then=Value(80)),
                    When(client_company_name__icontains=search_query, then=Value(70)),
                    When(client_email__icontains=search_query, then=Value(60)),
                    When(client_contact_number__icontains=search_query, then=Value(50)),
                    When(project_category__icontains=search_query, then=Value(40)),
                    When(lead_type__icontains=search_query, then=Value(30)),
                    When(requirement_description__icontains=search_query, then=Value(20)),
                    default=Value(10),
                    output_field=IntegerField(),
                )
            )

        # 2. Field-Specific Filters
        status_param = request.query_params.get("status")
        if status_param:
            leads = leads.filter(status__iexact=status_param.strip())

        lead_type_param = request.query_params.get("lead_type")
        if lead_type_param:
            leads = leads.filter(lead_type__iexact=lead_type_param.strip())

        category_param = request.query_params.get("project_category") or request.query_params.get("category")
        if category_param:
            leads = leads.filter(project_category__icontains=category_param.strip())

        client_is_param = request.query_params.get("client_is")
        if client_is_param:
            leads = leads.filter(client_is__iexact=client_is_param.strip())

        country_param = request.query_params.get("country_name") or request.query_params.get("country")
        if country_param:
            leads = leads.filter(country_name__icontains=country_param.strip())

        source_param = request.query_params.get("lead_generated_from") or request.query_params.get("source")
        if source_param:
            leads = leads.filter(lead_generated_from__icontains=source_param.strip())

        follow_up_param = request.query_params.get("next_follow_up")
        if follow_up_param:
            leads = leads.filter(next_follow_up__iexact=follow_up_param.strip())

        # Date Filters
        date_from = request.query_params.get("date_from") or request.query_params.get("start_date")
        if date_from:
            leads = leads.filter(created_at__date__gte=date_from)

        date_to = request.query_params.get("date_to") or request.query_params.get("end_date")
        if date_to:
            leads = leads.filter(created_at__date__lte=date_to)

        # 3. Sorting / Ordering
        ordering = request.query_params.get("ordering")
        valid_order_fields = [
            "created_at", "-created_at",
            "updated_at", "-updated_at",
            "client_full_name", "-client_full_name",
            "client_company_name", "-client_company_name",
            "status", "-status",
            "lead_type", "-lead_type",
        ]
        if ordering and ordering in valid_order_fields:
            leads = leads.order_by(ordering)
        elif search_query:
            leads = leads.order_by("-relevance_score", "-created_at")
        else:
            leads = leads.order_by("-created_at")

        # 4. Pagination (Optional - if requested via ?page=)
        total_count = leads.count()
        page = request.query_params.get("page")
        page_size = request.query_params.get("page_size", 20)

        if page:
            try:
                page = int(page)
                page_size = int(page_size)
                start = (page - 1) * page_size
                end = start + page_size
                paginated_leads = leads[start:end]
                serializer = LeadSerializer(paginated_leads, many=True)
                return Response({
                    "success": True,
                    "count": total_count,
                    "page": page,
                    "page_size": page_size,
                    "total_pages": (total_count + page_size - 1) // page_size if page_size > 0 else 1,
                    "data": serializer.data
                }, status=status.HTTP_200_OK)
            except (ValueError, TypeError):
                pass

        serializer = LeadSerializer(leads, many=True)
        return Response({
            "success": True,
            "count": total_count,
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


# --- Schedule Callback API Views ---

class ScheduleCallbackListCreateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, lead_id=None):
        """
        List & Search scheduled callbacks:
        - Optional filter by lead_id (URL parameter or query param)
        - Multi-keyword search (?search= or ?q=) across client name, phone, notes, lead_id
        - Filters (?status=, ?type=, ?date_from=, ?date_to=)
        - Ordering (?ordering=)
        """
        user = request.user
        if getattr(user, "role", "") == "ADMIN" or user.is_superuser:
            callbacks = ScheduleCallback.objects.all()
        else:
            callbacks = ScheduleCallback.objects.filter(
                Q(type="Public") | Q(created_by=user) | Q(lead__created_by=user)
            )

        # Filter: Whole team vs My callbacks
        scope = request.query_params.get("scope") or request.query_params.get("filter")
        my_callbacks = request.query_params.get("my_callbacks")
        created_by_param = request.query_params.get("created_by")

        if (
            (my_callbacks and my_callbacks.lower() in ["true", "1", "yes"])
            or (scope and scope.lower() in ["my", "me", "my_callbacks", "personal"])
            or (created_by_param and created_by_param.lower() in ["me", "my"])
        ):
            callbacks = callbacks.filter(created_by=user)
        elif created_by_param and created_by_param.isdigit():
            callbacks = callbacks.filter(created_by_id=int(created_by_param))

        # 1. Filter by Lead (from URL or Query Param)
        lead_query = lead_id or request.query_params.get("lead_id") or request.query_params.get("lead")
        if lead_query:
            lead_query_str = str(lead_query).strip()
            if lead_query_str.upper().startswith("DR-LEAD-"):
                num_str = lead_query_str.upper().replace("DR-LEAD-", "").lstrip("0")
                lead_pk = int(num_str) if (num_str and num_str.isdigit()) else 0
            elif lead_query_str.isdigit():
                lead_pk = int(lead_query_str)
            else:
                lead_pk = None

            if lead_pk is not None:
                callbacks = callbacks.filter(lead_id=lead_pk)

        # 2. Search (?search= or ?q=)
        search_query = request.query_params.get("search") or request.query_params.get("q")
        if search_query:
            search_query = search_query.strip()
            tokens = search_query.split()
            for token in tokens:
                token_q = (
                    Q(lead__client_full_name__icontains=token)
                    | Q(lead__client_company_name__icontains=token)
                    | Q(lead__client_email__icontains=token)
                    | Q(phone__icontains=token)
                    | Q(notes__icontains=token)
                    | Q(type__icontains=token)
                    | Q(status__icontains=token)
                )
                if token.isdigit():
                    token_q |= Q(id=int(token)) | Q(lead_id=int(token))
                elif token.upper().startswith("DR-LEAD-"):
                    num_str = token.upper().replace("DR-LEAD-", "").lstrip("0")
                    if num_str.isdigit():
                        token_q |= Q(lead_id=int(num_str))

                callbacks = callbacks.filter(token_q)

        # 3. Filters
        type_param = request.query_params.get("type")
        if type_param:
            callbacks = callbacks.filter(type__iexact=type_param.strip())

        status_param = request.query_params.get("status")
        if status_param:
            callbacks = callbacks.filter(status__iexact=status_param.strip())

        date_from = request.query_params.get("date_from") or request.query_params.get("start_date")
        if date_from:
            callbacks = callbacks.filter(date_time__date__gte=date_from)

        date_to = request.query_params.get("date_to") or request.query_params.get("end_date")
        if date_to:
            callbacks = callbacks.filter(date_time__date__lte=date_to)

        # 4. Ordering
        ordering = request.query_params.get("ordering", "date_time")
        valid_orders = ["date_time", "-date_time", "created_at", "-created_at", "status", "-status"]
        if ordering in valid_orders:
            callbacks = callbacks.order_by(ordering)
        else:
            callbacks = callbacks.order_by("date_time")

        # 5. Pagination (Optional)
        total_count = callbacks.count()
        page = request.query_params.get("page")
        page_size = request.query_params.get("page_size", 20)

        if page:
            try:
                page = int(page)
                page_size = int(page_size)
                start = (page - 1) * page_size
                end = start + page_size
                serializer = ScheduleCallbackSerializer(callbacks[start:end], many=True)
                return Response({
                    "success": True,
                    "count": total_count,
                    "page": page,
                    "page_size": page_size,
                    "total_pages": (total_count + page_size - 1) // page_size if page_size > 0 else 1,
                    "data": serializer.data
                }, status=status.HTTP_200_OK)
            except (ValueError, TypeError):
                pass

        serializer = ScheduleCallbackSerializer(callbacks, many=True)
        return Response({
            "success": True,
            "count": total_count,
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def post(self, request, lead_id=None):
        """
        Schedule a new callback (POST)
        """
        data = request.data.copy() if hasattr(request.data, "copy") else dict(request.data)
        if lead_id and "lead_id" not in data and "lead" not in data:
            data["lead_id"] = lead_id

        serializer = ScheduleCallbackSerializer(data=data)
        if serializer.is_valid():
            callback = serializer.save(created_by=request.user)
            return Response({
                "success": True,
                "message": "Callback scheduled successfully.",
                "data": ScheduleCallbackSerializer(callback).data
            }, status=status.HTTP_201_CREATED)

        return Response({
            "success": False,
            "errors": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


class ScheduleCallbackDetailAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, pk, user):
        try:
            if getattr(user, "role", "") == "ADMIN" or user.is_superuser:
                return ScheduleCallback.objects.get(pk=pk)
            return ScheduleCallback.objects.get(
                Q(pk=pk) & (Q(created_by=user) | Q(lead__created_by=user) | Q(type="Public"))
            )
        except ScheduleCallback.DoesNotExist:
            return None

    def get(self, request, pk):
        callback = self.get_object(pk, request.user)
        if not callback:
            return Response({
                "success": False,
                "message": "Callback not found or permission denied."
            }, status=status.HTTP_404_NOT_FOUND)

        serializer = ScheduleCallbackSerializer(callback)
        return Response({
            "success": True,
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def put(self, request, pk):
        callback = self.get_object(pk, request.user)
        if not callback:
            return Response({
                "success": False,
                "message": "Callback not found or permission denied."
            }, status=status.HTTP_404_NOT_FOUND)

        serializer = ScheduleCallbackSerializer(callback, data=request.data, partial=True)
        if serializer.is_valid():
            updated = serializer.save()
            return Response({
                "success": True,
                "message": "Callback updated successfully.",
                "data": ScheduleCallbackSerializer(updated).data
            }, status=status.HTTP_200_OK)

        return Response({
            "success": False,
            "errors": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk):
        return self.put(request, pk)

    def delete(self, request, pk):
        callback = self.get_object(pk, request.user)
        if not callback:
            return Response({
                "success": False,
                "message": "Callback not found or permission denied."
            }, status=status.HTTP_404_NOT_FOUND)

        lead_ref = callback.lead.lead_id if callback.lead else f"Lead #{callback.lead_id}"
        callback.delete()
        return Response({
            "success": True,
            "message": f"Callback for {lead_ref} deleted successfully.",
            "data": {
                "id": pk
            }
        }, status=status.HTTP_200_OK)

    def post(self, request, pk):
        if "delete" in request.path:
            return self.delete(request, pk)
        return self.put(request, pk)


# --- Email Campaign API Views (CRUD) ---

class EmailCampaignListCreateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        List & Search email campaigns:
        - Scoped to user unless Admin/Superuser
        - Search (?search= or ?q=) across name, subject, message, category, country, lead_type, status, campaign_id
        - Attribute filters (?status=, ?lead_type=, ?category=, ?country=, ?client_is=, ?scope=)
        - Ordering (?ordering=)
        - Pagination (?page= & ?page_size=)
        """
        user = request.user
        if getattr(user, "role", "") == "ADMIN" or user.is_superuser:
            campaigns = EmailCampaign.objects.all()
        else:
            campaigns = EmailCampaign.objects.filter(created_by=user)

        # 1. Scope filter (?scope=my vs ?scope=team)
        scope = request.query_params.get("scope")
        if scope and scope.lower() in ["my", "me", "personal"]:
            campaigns = campaigns.filter(created_by=user)

        # 2. Search (?search= or ?q=)
        search_query = request.query_params.get("search") or request.query_params.get("q")
        if search_query:
            search_query = search_query.strip()
            tokens = search_query.split()
            for token in tokens:
                token_q = (
                    Q(name__icontains=token)
                    | Q(subject__icontains=token)
                    | Q(message__icontains=token)
                    | Q(category__icontains=token)
                    | Q(country__icontains=token)
                    | Q(lead_type__icontains=token)
                    | Q(client_is__icontains=token)
                    | Q(status__icontains=token)
                )
                if token.isdigit():
                    token_q |= Q(id=int(token))
                elif token.upper().startswith("CAMP-"):
                    num_str = token.upper().replace("CAMP-", "").lstrip("0")
                    if num_str.isdigit():
                        token_q |= Q(id=int(num_str))

                campaigns = campaigns.filter(token_q)

        # 3. Attribute filters
        status_param = request.query_params.get("status")
        if status_param:
            campaigns = campaigns.filter(status__iexact=status_param.strip())

        lead_type_param = request.query_params.get("lead_type")
        if lead_type_param:
            campaigns = campaigns.filter(lead_type__iexact=lead_type_param.strip())

        category_param = request.query_params.get("category")
        if category_param:
            campaigns = campaigns.filter(category__icontains=category_param.strip())

        country_param = request.query_params.get("country")
        if country_param:
            campaigns = campaigns.filter(country__icontains=country_param.strip())

        client_is_param = request.query_params.get("client_is")
        if client_is_param:
            campaigns = campaigns.filter(client_is__iexact=client_is_param.strip())

        # 4. Ordering
        ordering = request.query_params.get("ordering", "-created_at")
        valid_orders = [
            "created_at", "-created_at",
            "name", "-name",
            "status", "-status",
            "total_leads_matched", "-total_leads_matched"
        ]
        if ordering in valid_orders:
            campaigns = campaigns.order_by(ordering)
        else:
            campaigns = campaigns.order_by("-created_at")

        # 5. Pagination
        total_count = campaigns.count()
        page = request.query_params.get("page")
        page_size = request.query_params.get("page_size", 20)

        if page:
            try:
                page = int(page)
                page_size = int(page_size)
                start = (page - 1) * page_size
                end = start + page_size
                paginated = campaigns[start:end]
                serializer = EmailCampaignSerializer(paginated, many=True)
                return Response({
                    "success": True,
                    "count": total_count,
                    "page": page,
                    "page_size": page_size,
                    "total_pages": (total_count + page_size - 1) // page_size if page_size > 0 else 1,
                    "data": serializer.data
                }, status=status.HTTP_200_OK)
            except (ValueError, TypeError):
                pass

        serializer = EmailCampaignSerializer(campaigns, many=True)
        return Response({
            "success": True,
            "count": total_count,
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def post(self, request):
        """
        Create a new Email Campaign (POST)
        """
        serializer = EmailCampaignSerializer(data=request.data)
        if serializer.is_valid():
            campaign = serializer.save(created_by=request.user)
            campaign.total_leads_matched = campaign.get_matching_leads_queryset().count()
            campaign.save(update_fields=["total_leads_matched"])
            return Response({
                "success": True,
                "message": f"Email campaign '{campaign.name}' created successfully.",
                "data": EmailCampaignSerializer(campaign).data
            }, status=status.HTTP_201_CREATED)

        return Response({
            "success": False,
            "errors": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


class EmailCampaignDetailAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, pk, user):
        try:
            if getattr(user, "role", "") == "ADMIN" or user.is_superuser:
                return EmailCampaign.objects.get(pk=pk)
            return EmailCampaign.objects.get(pk=pk, created_by=user)
        except EmailCampaign.DoesNotExist:
            return None

    def get(self, request, pk):
        campaign = self.get_object(pk, request.user)
        if not campaign:
            return Response({
                "success": False,
                "message": "Campaign not found or permission denied."
            }, status=status.HTTP_404_NOT_FOUND)

        serializer = EmailCampaignSerializer(campaign)
        return Response({
            "success": True,
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def put(self, request, pk):
        campaign = self.get_object(pk, request.user)
        if not campaign:
            return Response({
                "success": False,
                "message": "Campaign not found or permission denied."
            }, status=status.HTTP_404_NOT_FOUND)

        serializer = EmailCampaignSerializer(campaign, data=request.data, partial=True)
        if serializer.is_valid():
            updated = serializer.save()
            updated.total_leads_matched = updated.get_matching_leads_queryset().count()
            updated.save(update_fields=["total_leads_matched"])
            return Response({
                "success": True,
                "message": "Campaign updated successfully.",
                "data": EmailCampaignSerializer(updated).data
            }, status=status.HTTP_200_OK)

        return Response({
            "success": False,
            "errors": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk):
        return self.put(request, pk)

    def delete(self, request, pk):
        campaign = self.get_object(pk, request.user)
        if not campaign:
            return Response({
                "success": False,
                "message": "Campaign not found or permission denied."
            }, status=status.HTTP_404_NOT_FOUND)

        camp_id = campaign.campaign_id or f"ID #{campaign.id}"
        camp_name = campaign.name
        campaign.delete()

        return Response({
            "success": True,
            "message": f"Campaign '{camp_name}' ({camp_id}) deleted successfully.",
            "data": {
                "id": pk,
                "campaign_id": camp_id
            }
        }, status=status.HTTP_200_OK)

    def post(self, request, pk):
        if "delete" in request.path:
            return self.delete(request, pk)
        return self.put(request, pk)


class EmailCampaignLeadsAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        """
        Get all leads matching an existing campaign's audience
        """
        try:
            if getattr(request.user, "role", "") == "ADMIN" or request.user.is_superuser:
                campaign = EmailCampaign.objects.get(pk=pk)
            else:
                campaign = EmailCampaign.objects.get(pk=pk, created_by=request.user)
        except EmailCampaign.DoesNotExist:
            return Response({
                "success": False,
                "message": "Campaign not found or permission denied."
            }, status=status.HTTP_404_NOT_FOUND)

        matching_qs = campaign.get_matching_leads_queryset(user=request.user)
        count = matching_qs.count()

        page = request.query_params.get("page")
        page_size = request.query_params.get("page_size", 50)
        if page:
            try:
                page = int(page)
                page_size = int(page_size)
                start = (page - 1) * page_size
                end = start + page_size
                matching_qs = matching_qs[start:end]
            except (ValueError, TypeError):
                pass

        leads_data = [
            {
                "id": lead.id,
                "lead_id": lead.lead_id,
                "client_full_name": lead.client_full_name,
                "client_email": lead.client_email,
                "client_company_name": lead.client_company_name,
                "lead_type": lead.lead_type,
                "project_category": lead.project_category,
                "country_name": lead.country_name,
                "status": lead.status,
            }
            for lead in matching_qs
        ]

        return Response({
            "success": True,
            "campaign_id": campaign.campaign_id,
            "campaign_name": campaign.name,
            "matching_leads_count": count,
            "data": leads_data
        }, status=status.HTTP_200_OK)


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


# --- Department Reports: Lead Generation Report API & Web Views ---

class LeadGenerationReportAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        is_admin = getattr(user, "role", "") == "ADMIN" or user.is_superuser
        if is_admin:
            leads = Lead.objects.all()
        else:
            leads = Lead.objects.filter(created_by=user)

        now = timezone.now()
        today = now.date()
        start_of_month = today.replace(day=1)

        date_from_str = request.query_params.get("date_from") or request.query_params.get("start_date")
        date_to_str = request.query_params.get("date_to") or request.query_params.get("end_date")

        def parse_date(d_str):
            if not d_str:
                return None
            for fmt in ("%Y-%m-%d", "%d-%m-%Y", "%Y/%m/%d", "%d/%m/%Y"):
                try:
                    return datetime.datetime.strptime(d_str.strip(), fmt).date()
                except ValueError:
                    continue
            return None

        date_from = parse_date(date_from_str) if date_from_str else start_of_month
        date_to = parse_date(date_to_str) if date_to_str else today

        if date_from and date_to and date_from > date_to:
            date_from, date_to = date_to, date_from

        if date_from:
            leads = leads.filter(created_at__date__gte=date_from)
        if date_to:
            leads = leads.filter(created_at__date__lte=date_to)

        total_leads = leads.count()
        hot_leads = leads.filter(lead_type__iexact="Hot").count()
        worked_upon = leads.exclude(status__iexact="Open").count()
        converted = leads.filter(status__iexact="Converted").count()
        conversion_pct = round((converted / total_leads * 100), 1) if total_leads > 0 else 0.0

        # Leads per day (day by day in date_from -> date_to range)
        leads_per_day = []
        if date_from and date_to:
            delta = (date_to - date_from).days
            step_days = min(max(delta + 1, 1), 62)
            for i in range(step_days):
                curr_date = date_from + timedelta(days=i)
                day_leads_count = leads.filter(created_at__date=curr_date).count()
                leads_per_day.append({
                    "date": curr_date.strftime("%Y-%m-%d"),
                    "day": curr_date.strftime("%d"),
                    "count": day_leads_count,
                })

        # By Executive Table
        by_executive = []
        creator_ids = set(leads.values_list("created_by", flat=True))
        for c_id in creator_ids:
            if not c_id:
                continue
            c_user = User.objects.filter(id=c_id).first()
            if not c_user:
                continue
            c_leads = leads.filter(created_by=c_user)
            c_gen = c_leads.count()
            c_hot = c_leads.filter(lead_type__iexact="Hot").count()
            c_warm = c_leads.filter(lead_type__iexact="Warm").count()
            c_worked = c_leads.exclude(status__iexact="Open").count()
            c_conv = c_leads.filter(status__iexact="Converted").count()
            c_conv_pct = f"{round((c_conv / c_gen * 100))}%" if c_gen > 0 else "0%"
            c_name = f"{c_user.first_name} {c_user.last_name}".strip() or c_user.email.split("@")[0].capitalize()
            by_executive.append({
                "executive": c_name,
                "generated": c_gen,
                "hot": c_hot,
                "warm": c_warm,
                "worked_by_sales": c_worked,
                "converted": c_conv,
                "conversion": c_conv_pct,
            })
        by_executive.sort(key=lambda x: x["generated"], reverse=True)

        # 1. Project Category Breakdown
        category_counts = leads.values("project_category").annotate(count=Count("id")).order_by("-count")
        by_project_category = [{"name": item["project_category"] or "Other", "count": item["count"]} for item in category_counts]

        # 2. Source Breakdown
        source_counts = leads.values("lead_generated_from").annotate(count=Count("id")).order_by("-count")
        by_source = [{"name": item["lead_generated_from"] or "Direct", "count": item["count"]} for item in source_counts]

        # 3. Country Breakdown
        country_counts = leads.values("country_name").annotate(count=Count("id")).order_by("-count")
        by_country = [{"name": item["country_name"] or "Unknown", "count": item["count"]} for item in country_counts]

        # 4. Lead Type Breakdown
        type_counts = leads.values("lead_type").annotate(count=Count("id")).order_by("-count")
        by_lead_type = [{"name": item["lead_type"] or "Cold", "count": item["count"]} for item in type_counts]

        # 5. Call Status Breakdown
        call_status_counts = {"Answered": 0, "Whatsapp Only": 0, "Not Answered": 0, "Call back later": 0, "Busy": 0}
        callbacks_qs = ScheduleCallback.objects.filter(lead__in=leads)
        lead_callback_map = {}
        for cb in callbacks_qs:
            lead_callback_map.setdefault(cb.lead_id, []).append(cb)

        for l in leads:
            cbs = lead_callback_map.get(l.id, [])
            status_assigned = False
            for cb in cbs:
                notes_lower = (cb.notes or "").lower()
                if "whatsapp" in notes_lower or l.lead_generated_from == "WhatsApp":
                    call_status_counts["Whatsapp Only"] += 1
                    status_assigned = True
                    break
                elif "busy" in notes_lower:
                    call_status_counts["Busy"] += 1
                    status_assigned = True
                    break
                elif "not answered" in notes_lower or "no answer" in notes_lower:
                    call_status_counts["Not Answered"] += 1
                    status_assigned = True
                    break
                elif cb.status == "Pending":
                    call_status_counts["Call back later"] += 1
                    status_assigned = True
                    break
                elif cb.status == "Completed":
                    call_status_counts["Answered"] += 1
                    status_assigned = True
                    break

            if not status_assigned:
                if l.lead_generated_from == "WhatsApp":
                    call_status_counts["Whatsapp Only"] += 1
                elif l.status in ["In Progress", "Converted", "Closed"]:
                    call_status_counts["Answered"] += 1
                elif l.status == "Lost":
                    call_status_counts["Not Answered"] += 1
                elif l.next_follow_up == "Yes":
                    call_status_counts["Call back later"] += 1
                else:
                    call_status_counts["Answered"] += 1

        by_call_status = [{"name": k, "count": v} for k, v in sorted(call_status_counts.items(), key=lambda x: x[1], reverse=True) if v > 0]
        if not by_call_status:
            by_call_status = [{"name": k, "count": v} for k, v in call_status_counts.items()]

        # 6. Passed to Sales Executive
        passed_to_counts = []
        for exec_info in by_executive:
            passed_to_counts.append({"name": exec_info["executive"], "count": exec_info["generated"]})

        serializer = LeadSerializer(leads[:500], many=True)

        return Response({
            "success": True,
            "data": {
                "date_from": date_from.strftime("%Y-%m-%d"),
                "date_to": date_to.strftime("%Y-%m-%d"),
                "date_from_display": date_from.strftime("%d-%m-%Y"),
                "date_to_display": date_to.strftime("%d-%m-%Y"),
                "summary": {
                    "leads_generated": total_leads,
                    "hot_leads": hot_leads,
                    "worked_upon": worked_upon,
                    "converted": converted,
                    "conversion_pct": conversion_pct,
                },
                "leads_per_day": leads_per_day,
                "by_executive": by_executive,
                "by_project_category": by_project_category,
                "by_source": by_source,
                "by_country": by_country,
                "by_lead_type": by_lead_type,
                "by_call_status": by_call_status,
                "passed_to_executive": passed_to_counts,
                "leads": serializer.data,
            }
        }, status=status.HTTP_200_OK)


@login_required(login_url="login")
def reports_web_view(request):
    if request.headers.get("Accept", "").startswith("application/json") or request.content_type == "application/json":
        return LeadGenerationReportAPIView.as_view()(request)
    return dashboard_view(request, active_tab="reports")
