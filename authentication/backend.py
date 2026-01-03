from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.models import User
from .utils import decode_token

class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')

        if not auth_header:
            return None
        
        try:
            prefix, token = auth_header.split(" ")
            if prefix.lower() != 'bearer':
                return None
        except ValueError:
            raise AuthenticationFailed('Invalid or Expired Token')
        
        payload = decode_token(token)

        if not payload:
            raise AuthenticationFailed('Invalid or Expired Token')
        
        if payload.get('type') != 'access':
            raise AuthenticationFailed('Invalid token type') 
        
        user_id = payload.get('user_id')
        
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise AuthenticationFailed('User not found')
        
        return (user, None)