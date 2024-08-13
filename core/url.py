from django.urls import path
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)
from core import  routing, views
urlpatterns = [
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('verify-email/', views.VerifyUserEmail.as_view(), name='verify'),
    path('change-default-password/', views.ChangeDefaultPasswordView.as_view(), name='change-default-password'),
    path('password-reset/', views.PasswordResetRequestView.as_view(), name='password-reset'),
    path('password-reset-confirm/<uidb64>/<token>/', views.PasswordResetConfirm.as_view(), name='reset-password-confirm'),
    path('set-new-password/', views.SetNewPasswordView.as_view(), name='set-new-password'),
    path('authenticated_user/', views.GetAuthenticatedUser.as_view(), name='authenticated_user')
]
urlpatterns += routing.router.urls