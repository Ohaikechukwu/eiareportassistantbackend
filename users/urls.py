from django.urls import path
from .views import (
    RegisterView,
    CustomTokenObtainPairView,
    CustomTokenRefreshView,
    LogoutView,
    UserDetailView,
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', CustomTokenObtainPairView.as_view(), name='login'),
    path('refresh/', CustomTokenRefreshView.as_view(), name='refresh'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('me/', UserDetailView.as_view(), name='user-detail'),
]