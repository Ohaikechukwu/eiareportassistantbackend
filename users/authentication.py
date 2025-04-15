from rest_framework_simplejwt.authentication import JWTAuthentication
from django.conf import settings
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

class CustomJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        header = self.get_header(request)
        
        if header is None:
            raw_token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE']) or None
            print(raw_token)
        else:
            raw_token = self.get_raw_token(header)
            
        if raw_token is None:
            return None

        validated_token = self.get_validated_token(raw_token)
        return self.get_user(validated_token), validated_token

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        
        # Add custom claims
        token['first_name'] = user.first_name
        token['last_name'] = user.last_name
        token['email'] = user.email
        token['phone'] = user.phone
        token['department'] = user.department
        token['division'] = user.division
        
        return token