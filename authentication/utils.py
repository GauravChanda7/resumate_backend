import jwt
from datetime import datetime, timedelta, timezone
from django.conf import settings

def generate_access_token(user):
    payload = {
        'user_id' : user.id,
        'exp' : datetime.now(timezone.utc) + timedelta(minutes=15),
        'iat' : datetime.now(timezone.utc),
        'type' : 'access'
    }

    access_token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
    return access_token

def generate_refresh_token(user):
    payload = {
        'user_id' : user.id,
        'exp' : datetime.now(timezone.utc) + timedelta(days=7),
        'iat' : datetime.now(timezone.utc),
        'type' : 'refresh'
    }

    refresh_token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
    return refresh_token

def decode_token(token):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    

