from django.urls import path
from . import views

urlpatterns = [
    path('initial-setup/', views.initial_superadmin_setup, name='initial_superadmin_setup'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('invite-superadmin/', views.invite_superadmin, name='invite_superadmin'),
    path('verify-invitation/<uuid:token>/', views.verify_invitation, name='verify_invitation'),
    path('superadmin-signup/<uuid:token>/', views.superadmin_signup, name='superadmin_signup'),
]