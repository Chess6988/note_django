from django.urls import path
from . import views

app_name = 'roles'

urlpatterns = [
    path('', views.etudiant_signup, name='home'),  # New root URL for signup page
    path('signup/', views.etudiant_signup, name='etudiant_signup'),  # Keep this for direct access
    path('activate/<str:uidb64>/<str:token>/', views.activate_account, name='activate'),
    path('resend-activation/', views.resend_activation, name='resend_activation'),
    path('signin/', views.signin, name='signin'),
    path('invitation/<uuid:token>/', views.verify_invitation, name='verify_invitation'),
    path('signup/invited/<uuid:token>/', views.invited_signup, name='invited_signup'),
    path('send-invitation/', views.send_invitation, name='send_invitation'),
    path('etudiant/dashboard/', views.etudiant_dashboard, name='etudiant_dashboard'),
    path('enseignant/dashboard/', views.enseignant_dashboard, name='enseignant_dashboard'),
    path('admin/panel/', views.admin_panel, name='admin_panel'),
    path('superadmin/panel/', views.superadmin_panel, name='superadmin_panel'),
    path('logout/', views.logout_view, name='logout'),
    path('create_profile/', views.create_profile, name='create_profile'),
    path('home_etudiant/', views.home_etudiant, name='home_etudiant'),
]

