from django.contrib import messages
from django.contrib.auth import login
from django.shortcuts import render, redirect
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.urls import reverse
import uuid
from .models import User, Invitation, Etudiant, Admin, Enseignant
from .forms import DefaultSignUpForm, InvitedSignUpForm, InviteUserForm
from django.conf import settings
from django.utils import timezone
from datetime import timedelta

def signup_view(request):
    if request.method == 'POST':
        form = DefaultSignUpForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.role = 'etudiant'
            user.is_active = False
            user.save()  # Password is set by UserCreationForm
            Etudiant.objects.create(user=user, filiere=None, niveau=None)

            current_site = get_current_site(request)
            subject = 'Activate your account'
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            activation_link = reverse('roles:activate', kwargs={'uidb64': uid, 'token': token})
            activation_url = f"http://{current_site.domain}{activation_link}"

            message = render_to_string('roles/activation_email.html', {
                'user': user,
                'activation_url': activation_url
            })
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])

            return render(request, 'roles/signup.html', {'form': form, 'show_modal': True})
    else:
        form = DefaultSignUpForm()
    return render(request, 'roles/signup.html', {'form': form})

def invited_signup_view(request, token):
    try:
        invitation = Invitation.objects.get(pin=token, status='pending')
    except Invitation.DoesNotExist:
        messages.error(request, 'Invalid or expired invitation link.')
        return redirect('roles:signup')

    if request.method == 'POST':
        form = InvitedSignUpForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.email = invitation.invitee_email
            user.role = invitation.role
            user.is_active = False
            user.save()  # Password is set by UserCreationForm

            if user.role == 'enseignant':
                Enseignant.objects.create(user=user)
            elif user.role == 'admin':
                Admin.objects.create(user=user)

            invitation.status = 'accepted'
            invitation.save()

            current_site = get_current_site(request)
            subject = 'Activate your account'
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            activation_link = reverse('roles:activate', kwargs={'uidb64': uid, 'token': token})
            activation_url = f"http://{current_site.domain}{activation_link}"

            message = render_to_string('roles/activation_email.html', {
                'user': user,
                'activation_url': activation_url
            })
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])

            return redirect('roles:login')
    else:
        form = InvitedSignUpForm()
    return render(request, 'roles/signup.html', {'form': form, 'invitation': invitation})

@login_required
def invite_user_view(request):
    if request.user.role not in ['superadmin', 'admin']:
        messages.error(request, 'You do not have permission to invite users.')
        return redirect(f"{reverse('roles:login')}?next={request.path}")

    if request.method == 'POST':
        form = InviteUserForm(request.POST, user=request.user)
        if form.is_valid():
            email = form.cleaned_data['email']
            role = form.cleaned_data['role']
            pin = str(uuid.uuid4())
            invitation = Invitation.objects.create(
                invitee_email=email,
                role=role,
                pin=pin,
                inviter=request.user,
                expires_at=timezone.now() + timedelta(days=7),
                status='pending'
            )

            current_site = get_current_site(request)
            subject = 'You are invited to join'
            invitation_link = reverse('roles:invited_signup', kwargs={'token': pin})
            invitation_url = f"http://{current_site.domain}{invitation_link}"

            message = render_to_string('roles/invitation_email.html', {
                'role': role,
                'invitation_url': invitation_url
            })
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])

            messages.success(request, 'Invitation sent successfully.')
            return redirect('roles:invite')
    else:
        form = InviteUserForm(user=request.user)
    return render(request, 'roles/invite_user.html', {'form': form})

def activate_account(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, 'Account activated successfully. You can now log in.')
        return redirect('roles:login')
    else:
        messages.error(request, 'Invalid or expired activation link.')
        return redirect('roles:signup')

class CustomLoginView(LoginView):
    template_name = 'roles/login.html'
    def get_success_url(self):
        return self.request.user.get_redirect_url()