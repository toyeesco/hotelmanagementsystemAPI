
from . import views
from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView
)


urlpatterns = [
    path("signup/", views.UserCreationView.as_view(), name="signup"),
    path("logout/", views.LogoutAPIView.as_view(), name="logout"),
    path('jwt/create/', TokenObtainPairView.as_view(), name='jwt_create'),
    path('jwt/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path("jwt/verify/", TokenVerifyView.as_view(), name="token_verify"),
    path('profile-create/', views.ProfileListCreateView.as_view(), name='profile_create'),
    path('profile-detail/<int:id>/', views.ProfileDetailView.as_view(), name='profile_detail'),
    path('request-reset-email', views.RequestPasswordResetEmail.as_view(), name='request-reset-email'),
    path('password-reset/<uidb64>/<token>/', views.PasswordTokenCheckAPI.as_view(), name='password-reset-confirm'),
    path('password-reset-complete', views.SetNewPasswordAPIView.as_view(), name='password-reset-complete')
]

