from django.urls import path
from erp.views import (
    home,
    dashboard_view,
    SignupAPIView,
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

    # REST APIs
    path("signup/", SignupAPIView.as_view(), name="signup"),
    path("api/signup/", SignupAPIView.as_view(), name="api_signup"),
    path("api/login/", LoginAPIView.as_view(), name="api_login"),
    path("api/logout/", LogoutAPIView.as_view(), name="api_logout"),
    path("api/token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("api/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("api/token/verify/", TokenVerifyView.as_view(), name="token_verify"),
]
