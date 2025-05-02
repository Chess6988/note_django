from django.template.loader import render_to_string
from django.core.exceptions import ValidationError
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate
from django.contrib import messages
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.db import IntegrityError, DatabaseError
from django.contrib.auth.decorators import login_required
from django.urls import reverse
import logging
import random
from .models import User, Invitation, Etudiant, Enseignant, Admin
from .forms import DefaultSignUpForm, PinForm, ResendActivationForm, InvitationForm

logger = logging.getLogger(__name__)

def send_activation_email(user, request):
    """Send an activation email with a 24-hour token."""
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    activation_link = request.build_absolute_uri(
        reverse('roles:activate', kwargs={'uidb64': uid, 'token': token})  # Namespaced
    )
    subject = "Activate Your Account"
    message = render_to_string('activation_email.html', {
        'user': user,
        'activation_link': activation_link,
    })
    try:
        send_mail(subject, message, 'from@example.com', [user.email], html_message=message)
    except Exception as e:
        logger.error(f"Failed to send activation email to {user.email}: {e}")
        raise

def etudiant_signup(request):
    """Handle Etudiant self-registration."""
    if request.user.is_authenticated:
        return redirect(request.user.get_redirect_url())
    if request.method == 'POST':
        form = DefaultSignUpForm(request.POST)
        if form.is_valid():
            try:
                user = form.save(commit=False)
                user.role = 'etudiant'
                user.is_active = False
                user.save()
                Etudiant.objects.create(user=user)  # Create Etudiant instance
           
                send_activation_email(user, request)
                messages.success(request, 'Account created! Check your email to activate.')
                return redirect('roles:signin')
            except IntegrityError:
                messages.error(request, 'Username or email already exists.')
            except DatabaseError as e:
                logger.error(f"Database error during signup: {e}")
                messages.error(request, 'An error occurred. Please try again later.')
            except Exception as e:
                logger.error(f"Unexpected error during signup: {e}")
                messages.error(request, 'An unexpected error occurred.')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = DefaultSignUpForm()
    return render(request, 'roles/signup.html', {'form': form})


def activate_account(request, uidb64, token):
    """Activate user account via email token."""
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, 'Account activated! Please sign in.')
        return redirect('roles:signin')  # Namespaced
    else:
        messages.error(request, 'Invalid or expired activation link.')
        return redirect('roles:resend_activation')  # Namespaced

def resend_activation(request):
    """Resend activation email."""
    if request.method == 'POST':
        form = ResendActivationForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                user = User.objects.get(email=email, is_active=False)
                send_activation_email(user, request)
                messages.success(request, 'Activation email resent. Check your email.')
            except User.DoesNotExist:
                messages.error(request, 'No inactive account found with this email.')
            except Exception as e:
                logger.error(f"Error resending activation: {e}")
                messages.error(request, 'An error occurred. Please try again.')
            return redirect('roles:signin')  # Namespaced
    else:
        form = ResendActivationForm()
    return render(request, 'roles/resend_activation.html', {'form': form})

def signin(request):
    """Handle user login."""
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return redirect(user.get_redirect_url())
        else:
            messages.error(request, 'Invalid username or password.')
    return render(request, 'roles/signin.html')

def verify_invitation(request, token):
    """Verify invitation PIN."""
    invitation = get_object_or_404(Invitation, token=token, status='pending')
    if invitation.is_expired():
        messages.error(request, 'Invitation has expired.')
        return redirect('roles:signin')
    if invitation.attempt_count >= 3:
        messages.error(request, 'Invitation is invalidated due to too many attempts.')
        return redirect('roles:signin')
    if request.method == 'POST':
        form = PinForm(request.POST)
        if form.is_valid():
            pin = form.cleaned_data['pin']
            logger.debug(f"PIN valid: {form.is_valid()}, PIN check: {invitation.check_pin(pin)}")
            if invitation.check_pin(pin):
                return redirect('roles:invited_signup', token=token)
            else:
                invitation.attempt_count += 1
                if invitation.attempt_count >= 3:
                    invitation.status = 'invalidated'
                invitation.save()
                messages.error(request, f'Incorrect PIN. {3 - invitation.attempt_count} attempts left.')
        else:
            messages.error(request, 'Please enter a valid PIN.')
    else:
        form = PinForm()
    return render(request, 'roles/verify_invitation.html', {'form': form, 'token': token})

def invited_signup(request, token):
    """Handle signup for invited roles."""
    invitation = get_object_or_404(Invitation, token=token, status='pending')
    if invitation.is_expired() or invitation.attempt_count >= 3:
        messages.error(request, 'Invitation is no longer valid.')
        return redirect('roles:signin')  # Namespaced
    if request.method == 'POST':
        form = DefaultSignUpForm(request.POST)
        if form.is_valid():
            try:
                user = form.save(commit=False)
                user.role = invitation.role
                user.email = invitation.email
                user.is_active = False
                user.save()
                if user.role == 'admin':
                    Admin.objects.create(user=user)
                elif user.role == 'enseignant':
                    Enseignant.objects.create(user=user)
                send_activation_email(user, request)
                invitation.status = 'accepted'
                invitation.accepted_by = user
                invitation.save()
                messages.success(request, 'Account created! Check your email to activate.')
                return redirect('roles:signin')  # Namespaced
            except IntegrityError:
                messages.error(request, 'Username or email already exists.')
            except DatabaseError as e:
                logger.error(f"Database error during invited signup: {e}")
                messages.error(request, 'An error occurred. Please try again.')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = DefaultSignUpForm(initial={'email': invitation.email})
        form.fields['email'].widget.attrs['readonly'] = True
    return render(request, 'roles/invited_signup.html', {'form': form, 'role': invitation.role})

@login_required
def send_invitation(request):
    """Send an invitation (Admin/Superadmin only)."""
    if request.user.role not in ['superadmin', 'admin']:
        messages.error(request, 'You do not have permission to send invitations.')
        return redirect('roles:signin')  # Namespaced
    if request.method == 'POST':
        form = InvitationForm(request.POST)
        if form.is_valid():
            try:
                invitation = form.save(commit=False)
                invitation.inviter = request.user
                raw_pin = ''.join([str(random.randint(0, 9)) for _ in range(6)])
                invitation.set_pin(raw_pin)
                invitation.save()
                link = request.build_absolute_uri(reverse('roles:verify_invitation', args=[invitation.token]))  # Namespaced
                messages.success(request, f'Invitation sent! Link: {link}, PIN: {raw_pin}')
                return redirect(request.user.get_redirect_url())
            except ValidationError as e:
                messages.error(request, str(e))
            except Exception as e:
                logger.error(f"Error sending invitation: {e}")
                messages.error(request, 'An error occurred while sending the invitation.')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = InvitationForm()
    return render(request, 'roles/send_invitation.html', {'form': form})

@login_required
def etudiant_dashboard(request):
    """Etudiant dashboard."""
    if request.user.role != 'etudiant':
        messages.error(request, 'Access denied.')
        return redirect('roles:signin')  # Namespaced
    return render(request, 'roles/etudiant_dashboard.html')

@login_required
def enseignant_dashboard(request):
    """Enseignant (Teacher) dashboard."""
    if request.user.role != 'enseignant':
        messages.error(request, 'Access denied.')
        return redirect('roles:signin')  # Namespaced
    return render(request, 'roles/enseignant_dashboard.html')

@login_required
def admin_panel(request):
    """Admin dashboard."""
    if request.user.role != 'admin':
        messages.error(request, 'Access denied.')
        return redirect('roles:signin')  # Namespaced
    return render(request, 'roles/admin_panel.html')

@login_required
def superadmin_panel(request):
    """Superadmin dashboard."""
    if request.user.role != 'superadmin':
        messages.error(request, 'Access denied.')
        return redirect('roles:signin')  # Namespaced
    return render(request, 'roles/superadmin_panel.html')