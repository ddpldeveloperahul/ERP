from django.urls import path
from erp.views import (
    home,
    dashboard_view,
    leads_manage_web_view,
    leads_add_web_view,
    callbacks_web_view,
    SignupAPIView,
    VerifyOTPAPIView,
    ResendOTPAPIView,
    ForgotPasswordRequestAPIView,
    ForgotPasswordVerifyOTPAPIView,
    ResetPasswordAPIView,
    LeadCreateAPIView,
    LeadDetailAPIView,
    ScheduleCallbackListCreateAPIView,
    ScheduleCallbackDetailAPIView,
    LoginAPIView,
    LogoutAPIView,
)
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

urlpatterns = [
    # Web UI Pages
    path("", home, name="root"),
    path("home/", home, name="home"),
    path("login/", LoginAPIView.as_view(), name="login"),
    path("login/", LoginAPIView.as_view(), name="erp_login"),
    path("dashboard/", dashboard_view, name="dashboard"),
    path("dashboard/", dashboard_view, name="erp_dashboard"),
    path("logout/", LogoutAPIView.as_view(), name="logout"),
    path("logout/", LogoutAPIView.as_view(), name="erp_logout"),

    # REST APIs - Signup & OTP Verification
    path("api/signup/", SignupAPIView.as_view(), name="api_signup"),
    path("signup/", SignupAPIView.as_view(), name="signup"),

    path("api/verify-otp/", VerifyOTPAPIView.as_view(), name="api_verify_otp"),
    path("verify-otp/", VerifyOTPAPIView.as_view(), name="verify_otp"),

    path("api/resend-otp/", ResendOTPAPIView.as_view(), name="api_resend_otp"),
    path("resend-otp/", ResendOTPAPIView.as_view(), name="resend_otp"),

    # REST APIs - Forgot & Reset Password
    path("api/forgot-password/", ForgotPasswordRequestAPIView.as_view(), name="api_forgot_password"),
    path("forgot-password/", ForgotPasswordRequestAPIView.as_view(), name="forgot_password"),

    path("api/forgot-password/verify-otp/", ForgotPasswordVerifyOTPAPIView.as_view(), name="api_forgot_password_verify"),
    path("forgot-password/verify-otp/", ForgotPasswordVerifyOTPAPIView.as_view(), name="forgot_password_verify"),

    path("api/forgot-password/reset-password/", ResetPasswordAPIView.as_view(), name="api_reset_password"),
    path("forgot-password/reset-password/", ResetPasswordAPIView.as_view(), name="reset_password"),

    # REST APIs - Lead Generation (Create, List, Update, Delete)
    path("api/leads/", LeadCreateAPIView.as_view(), name="api_leads"),
    path("api/leads/add/", LeadCreateAPIView.as_view(), name="api_add_lead"),
    path("api/leads/<int:pk>/", LeadDetailAPIView.as_view(), name="api_lead_detail"),
    path("api/leads/<int:pk>/update/", LeadDetailAPIView.as_view(), name="api_lead_update"),
    path("api/leads/<int:pk>/delete/", LeadDetailAPIView.as_view(), name="api_lead_delete"),

    # Web / Alias paths
    path("leads/", leads_manage_web_view, name="leads"),
    path("leads/add/", leads_add_web_view, name="add_lead"),
    path("leads/<int:pk>/", LeadDetailAPIView.as_view(), name="lead_detail"),
    path("leads/<int:pk>/update/", LeadDetailAPIView.as_view(), name="lead_update"),
    path("leads/<int:pk>/delete/", LeadDetailAPIView.as_view(), name="lead_delete"),

    # REST APIs - Schedule Callback for Leads (CRUD)
    path("api/callbacks/", ScheduleCallbackListCreateAPIView.as_view(), name="api_callbacks"),
    path("api/callbacks/schedule/", ScheduleCallbackListCreateAPIView.as_view(), name="api_schedule_callback"),
    path("api/callbacks/<int:pk>/", ScheduleCallbackDetailAPIView.as_view(), name="api_callback_detail"),
    path("api/callbacks/<int:pk>/update/", ScheduleCallbackDetailAPIView.as_view(), name="api_callback_update"),
    path("api/callbacks/<int:pk>/delete/", ScheduleCallbackDetailAPIView.as_view(), name="api_callback_delete"),
    path("api/leads/<int:lead_id>/callbacks/", ScheduleCallbackListCreateAPIView.as_view(), name="api_lead_callbacks"),

    # Web / Alias paths
    path("callbacks/", callbacks_web_view, name="callbacks"),
    path("callbacks/schedule/", callbacks_web_view, name="schedule_callback"),
    path("callbacks/<int:pk>/", ScheduleCallbackDetailAPIView.as_view(), name="callback_detail"),
    path("callbacks/<int:pk>/update/", ScheduleCallbackDetailAPIView.as_view(), name="callback_update"),
    path("callbacks/<int:pk>/delete/", ScheduleCallbackDetailAPIView.as_view(), name="callback_delete"),

    # REST APIs - Auth Session & JWT
    path("api/login/", LoginAPIView.as_view(), name="api_login"),
    path("api/logout/", LogoutAPIView.as_view(), name="api_logout"),
    path("api/token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("api/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("api/token/verify/", TokenVerifyView.as_view(), name="token_verify"),
]
