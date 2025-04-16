from django.urls import path
from . import views
from django.contrib.auth.views import LoginView

app_name = 'roles'

urlpatterns = [
    path('signup/', views.signup_view, name='signup'),
    path('signup/invite/<str:token>/', views.invited_signup_view, name='invited_signup'),
    path('login/', views.CustomLoginView.as_view(template_name='roles/login.html'), name='login'),  # Updated to CustomLoginView
    path('activate/<uidb64>/<token>/', views.activate_account, name='activate'),
    path('invite/', views.invite_user_view, name='invite'),
]