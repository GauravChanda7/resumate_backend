from django.urls import path
from .views import (
    RegisterView,
    LoginView,
    LogoutView,
    ChangePasswordView,
    PasswordResetRequestView,
    PasswordResetConfirmView,
    RefreshTokenView,
    GoogleLoginView
)

app_name = 'authentication'

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('token/refresh/', RefreshTokenView.as_view(), name='token_refresh'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('change_password/', ChangePasswordView.as_view(), name='change_password'),
    path('password/reset/', PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('password/confirm/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),

    path('google/', GoogleLoginView.as_view(), name='google_login'),
]