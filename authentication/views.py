from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from .utils import generate_access_token, generate_refresh_token, decode_token
from rest_framework import status
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import send_mail
from django.conf import settings
import requests
from urllib.parse import unquote

# Create your views here.
class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')
        confirm_password = request.data.get('confirm_password')

        if not username or not email or not password or not confirm_password:
            return Response({'error' : 'Username, Email and Password requires'}, status=status.HTTP_400_BAD_REQUEST)
        
        if User.objects.filter(username=username).exists():
            return Response({'error' : 'This username already exists'}, status=status.HTTP_400_BAD_REQUEST)
        
        if User.objects.filter(email=email).exists():
            return Response({'error' : 'This email already exist'}, status=status.HTTP_400_BAD_REQUEST)
        
        if password != confirm_password:
            return Response({'error' : 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)
        
        user = User.objects.create_user(username=username, email=email, password=password)

        return Response({'message' : 'User registered successfully'}, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(username=username, password=password)

        if user is not None:
            access_token = generate_access_token(user)
            refresh_token = generate_refresh_token(user)
            return Response({
                'access_token' : access_token,
                'refresh_token' : refresh_token, 
                'user_id' : user.id,
                'username' : user.username,
            }, status=status.HTTP_200_OK)
        else:
            return Response({'error' : 'Invalid Credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        

class RefreshTokenView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        refresh_token = request.data.get('refresh_token')

        if not refresh_token:
            return Response({'error' : 'Refresh token required'}, status=status.HTTP_400_BAD_REQUEST)
        
        payload = decode_token(refresh_token)

        if not payload:
            return Response({'error' : 'Invalid or expired refresh Token'}, status=status.HTTP_401_UNAUTHORIZED)
        
        if payload.get('type') != 'refresh':
            return Response({'error' : 'Invalid token type'}, status=status.HTTP_401_UNAUTHORIZED)
        
        user_id = payload.get("user_id")
        user = User.objects.filter(id=user_id).first()

        if not user:
            return Response({'error' : 'User not found'}, status=status.HTTP_401_UNAUTHORIZED)
        
        new_access_token = generate_access_token(user)

        return Response({'access_token' : new_access_token}, status=status.HTTP_200_OK)
    
        
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        return Response({'message' : 'User logged out successfully'})


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')
        new_confirm_password = request.data.get('new_confirm_password')

        if not user.check_password(old_password):
            return Response({'error' : 'Wrong old password'}, status=status.HTTP_400_BAD_REQUEST)
        
        
        if new_password != new_confirm_password:
            return Response({'error' : 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)
        
        if new_password == old_password:
            return Response({'error' : 'Enter a different password'}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()
        return Response({'message' : 'Password updated successfully'}, status=status.HTTP_200_OK)
     
    
class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')

        if not email:
            return Response({'error' : 'Enter your email id'}, status=status.HTTP_400_BAD_REQUEST)
        
        user = User.objects.filter(email=email).first()

        if user:
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))

            reset_link = f"http://localhost:3000/reset-password/{uid}/{token}/"

            send_mail(
                subject = "Password Reset Request",
                message = f"Click the link to reset your password: {reset_link}",
                from_email = settings.DEFAULT_FROM_EMAIL,
                recipient_list = [email],
                fail_silently = False
            )

        return Response({'message' : 'If your email is registered, you will recieve a reset link.'}, status=status.HTTP_200_OK)


class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, uidb64, token):
        new_password = request.data.get('new_password')
        confirm_new_password = request.data.get('confirm_new_password')

        if not new_password or not confirm_new_password:
            return Response({'error' : 'New password is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        if new_password != confirm_new_password:
            return Response({'error' : 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({'error' : 'Invalid Link'}, status=status.HTTP_400_BAD_REQUEST)
        
        if not default_token_generator.check_token(user, token):
            return Response({'error' : 'Link is Invalid or Expired'}, status=status.HTTP_400_BAD_REQUEST)
        
        user.set_password(new_password)
        user.save()

        return Response({'message' : 'Password has been reset successfully'}, status=status.HTTP_200_OK)
        

class GoogleLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        code = request.data.get('code')
        code = unquote(code)

        if not code:
            return Response({'error' : 'Authorisation code is required'} , status=status.HTTP_400_BAD_REQUEST)
        
        token_url = "https://oauth2.googleapis.com/token"
        token_data = {
            'code' : code,
            'client_id' : settings.GOOGLE_CLIENT_ID,
            'client_secret' : settings.GOOGLE_CLIENT_SECRET,
            'redirect_uri' : settings.GOOGLE_REDIRECT_URI,
            'grant_type' : 'authorization_code',
        }

        try:
            response = requests.post(token_url, data=token_data)
            response.raise_for_status()
            google_tokens = response.json()
        except requests.exceptions.RequestException as e:
            return Response({'error' : 'Failed to exchange code with Google'}, status=status.HTTP_400_BAD_REQUEST)
        
        access_token = google_tokens.get('access_token')

        user_info_url = 'https://www.googleapis.com/oauth2/v2/userinfo'

        try:
            user_response = requests.get(user_info_url, params={'access_token' : access_token})
            user_response.raise_for_status()
            user_info = user_response.json()
        except requests.exceptions.RequestException:
            return Response({'error' : 'Failed to exchange user info from Google'}, status=status.HTTP_400_BAD_REQUEST)

        email = user_info.get('email')
        
        if not email:
            return Response({'error' : 'Google account has no email'}, status=status.HTTP_400_BAD_REQUEST)
        
        user = User.objects.filter(email=email).first()

        if user:
            pass
        else:
            base_username = email.split('@')[0]
            username = base_username
            counter = 1
            while User.objects.filter(username=username).exists():
                username = f"{base_username}{counter}"
                counter += 1

            user = User.objects.create_user(username=username, email=email, password=None)

        access_token = generate_access_token(user)
        refresh_token = generate_refresh_token(user)

        return Response({
            'access_token' : access_token,
            'refresh_token' : refresh_token,
            'user_id' : user.id,
            'username' : user.username,
        }, status=status.HTTP_200_OK)
    


        
