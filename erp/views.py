from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.db.models import Q, Case, When, Value, IntegerField

from rest_framework import generics
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError

from erp.models import EmailOTP, Lead, ScheduleCallback
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
