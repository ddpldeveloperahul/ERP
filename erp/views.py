from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required

from rest_framework import generics
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError

from erp.serializers import SignupSerializer


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
        "email_verified": True,
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

            return Response({
                "success": True,
                "message": "Account created successfully.",
                "data": {
                    "id": user.id,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "email": user.email,
                    "role": user.role,
                }
            }, status=status.HTTP_201_CREATED)

        return Response({
            "success": False,
            "errors": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


# Login API View (Handles both Web UI & API requests)
class LoginAPIView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        if request.user.is_authenticated:
            return redirect("dashboard")
        return render(request, "login.html")

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

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
