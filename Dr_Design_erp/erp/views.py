from django.shortcuts import render
from  django.http import HttpResponse
# Create your views here.


def home(request):
    return HttpResponse("Hello, World!")


from rest_framework import generics
from rest_framework.permissions import AllowAny,IsAuthenticated

from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate, login

from .serializers import SignupSerializer


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


# Login API
class LoginAPIView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):

        email = request.data.get("email")
        password = request.data.get("password")

        # Authenticate user
        user = authenticate(request,email=email,password=password)
        if user is not None:
            login(request, user)  # Log the user in
            # Generate JWT tokens
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

        return Response({
            "success": False,
            "message": "Invalid email or password."
        }, status=status.HTTP_401_UNAUTHORIZED)
    

class LogoutAPIView(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):

        return Response({
            "success": True,
            "message": "Logout successful."
        }, status=status.HTTP_200_OK)