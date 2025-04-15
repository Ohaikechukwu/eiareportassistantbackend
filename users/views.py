from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from django.conf import settings
from django.contrib.auth import get_user_model
from .serializers import UserRegistrationSerializer, CustomTokenObtainPairSerializer
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from .authentication import CustomJWTAuthentication

from rest_framework_simplejwt.tokens import RefreshToken




User = get_user_model()

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserRegistrationSerializer
    
    def create(self, request, *args, **kwargs):
        print("Incoming data:", request.data)  # Keep this for debugging
        print("Content-Type:", request.content_type)
        
        # Check if data is nested inside a 'data' field
        if request.data and isinstance(request.data, dict) and 'data' in request.data:
            actual_data = request.data['data']
        else:
            actual_data = request.data
            
        serializer = self.get_serializer(data=actual_data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        
        # Generate tokens
        refresh = CustomTokenObtainPairSerializer.get_token(user)
        
        response = Response({
            "user": {
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'other_name': user.other_name,
                'phone': user.phone,
                'department': user.department,
                'division': user.division,
            },
            "message": "User created successfully",
        }, status=status.HTTP_201_CREATED)
        
        # Set cookies
        response.set_cookie(
            key=settings.SIMPLE_JWT['AUTH_COOKIE'],
            value=str(refresh.access_token),
            expires=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
            secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
            httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
            samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
        )
        
        response.set_cookie(
            key=settings.SIMPLE_JWT['REFRESH_COOKIE'],
            value=str(refresh),
            expires=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
            secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
            httponly=settings.SIMPLE_JWT['REFRESH_COOKIE_HTTP_ONLY'],
            samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
        )
        
        return response

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        
        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])
            
        response = Response(serializer.validated_data, status=status.HTTP_200_OK)
        
        # Set cookies
        response.set_cookie(
            key=settings.SIMPLE_JWT['AUTH_COOKIE'],
            value=serializer.validated_data['access'],
            expires=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
            secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
            httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
            samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
        )
        
        response.set_cookie(
            key=settings.SIMPLE_JWT['REFRESH_COOKIE'],
            value=serializer.validated_data['refresh'],
            expires=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
            secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
            httponly=settings.SIMPLE_JWT['REFRESH_COOKIE_HTTP_ONLY'],
            samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
        )
        
        return response

class CustomTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get(settings.SIMPLE_JWT['REFRESH_COOKIE'])
        print(f"Refresh token received: {'Present' if refresh_token else 'None'}")
        
        if refresh_token:
            request.data['refresh'] = refresh_token
            
        serializer = self.get_serializer(data=request.data)
        
        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])
            
        response = Response(serializer.validated_data, status=status.HTTP_200_OK)
        
        # Update access token cookie
        response.set_cookie(
            key=settings.SIMPLE_JWT['AUTH_COOKIE'],
            value=serializer.validated_data['access'],
            expires=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
            secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
            httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
            samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE'],
            path=settings.SIMPLE_JWT['AUTH_COOKIE_PATH'],
            domain=settings.SIMPLE_JWT['AUTH_COOKIE_DOMAIN'],
        )
        
        # If ROTATE_REFRESH_TOKENS is True, you should set the new refresh token too
        if 'refresh' in serializer.validated_data:
            response.set_cookie(
                key=settings.SIMPLE_JWT['REFRESH_COOKIE'],
                value=serializer.validated_data['refresh'],
                expires=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
                secure=settings.SIMPLE_JWT['REFRESH_COOKIE_SECURE'],
                httponly=settings.SIMPLE_JWT['REFRESH_COOKIE_HTTP_ONLY'],
                samesite=settings.SIMPLE_JWT['REFRESH_COOKIE_SAMESITE'],
                path=settings.SIMPLE_JWT['REFRESH_COOKIE_PATH'],
                domain=settings.SIMPLE_JWT['REFRESH_COOKIE_DOMAIN'],
            )
        
        return response

# class LogoutView(generics.GenericAPIView):
#     def post(self, request, *args, **kwargs):
#         response = Response({"message": "Successfully logged out."}, status=status.HTTP_200_OK)
        
#         # Delete cookies
#         response.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE'])
#         response.delete_cookie(settings.SIMPLE_JWT['REFRESH_COOKIE'])
        
#         return response


class LogoutView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            # Get refresh token from cookies or request body
            refresh_token = request.COOKIES.get(settings.SIMPLE_JWT['REFRESH_COOKIE']) or request.data.get('refresh')
            
            # If refresh token exists, blacklist it
            if refresh_token:
                try:
                    token = RefreshToken(refresh_token)
                    token.blacklist()
                except TokenError as e:
                    # Token might be expired or invalid - we'll still proceed with logout
                    print(f"Token blacklist error: {str(e)}")
            
            # Create response
            response = Response(
                {"message": "Successfully logged out."}, 
                status=status.HTTP_200_OK
            )
            
            # Delete cookies - simplified version without unsupported kwargs
            response.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE'])
            response.delete_cookie(settings.SIMPLE_JWT['REFRESH_COOKIE'])
            
            return response
            
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

class UserDetailView(APIView):
    authentication_classes = [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        if user.is_anonymous:
            return Response({'detail': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)
            
        data = {
            'id': str(user.id),
            'email': user.email,
            'first_name': user.first_name,
            'other_name': user.other_name,
            'last_name': user.last_name,
            'phone': user.phone,
            'department': user.department,
            'division': user.division
            # ... other fields
        }
        return Response(data)
    
    