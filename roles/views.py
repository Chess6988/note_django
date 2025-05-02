
from django.conf import settings
from django.template.loader import render_to_string
from django.core.exceptions import ValidationError
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate, logout
from django.contrib import messages
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator,   PasswordResetTokenGenerator
from django.core.mail import send_mail
from django.db import IntegrityError, DatabaseError
from django.contrib.auth.decorators import login_required
from django.urls import reverse
import logging
import random


from roles_project.settings import DEFAULT_FROM_EMAIL
from .models import User, Invitation, Etudiant, Enseignant, Admin
from .forms import DefaultSignUpForm, PinForm, ResendActivationForm, InvitationForm

logger = logging.getLogger(__name__)



class SignupTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        # Use username and email instead of pk for unsaved user
        return f"{user.username}{user.email}{timestamp}"
    
def send_activation_email(user_data, request):
    """Send an activation email with a 24-hour token using session data."""
    token = default_token_generator.make_token(user_data)  # Token based on user_data (not saved user)
    uid = urlsafe_base64_encode(force_bytes(user_data.pk))  # Temporary ID from session
    activation_link = request.build_absolute_uri(
        reverse('roles:activate', kwargs={'uidb64': uid, 'token': token})
    )
    subject = "Activate Your Account"
    message = render_to_string('activation_email.html', {
        'user': user_data,
        'activation_link': activation_link,
    })
    try:
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user_data.email], html_message=message, fail_silently=False)
    except Exception as e:
        logger.error(f"Failed to send activation email to {user_data.email}: {e}")
        raise

def etudiant_signup(request):
    """Handle Etudiant self-registration."""
    if request.user.is_authenticated and request.user.role == 'etudiant':
        return redirect(request.user.get_redirect_url())

    if request.method == 'POST':
        form = DefaultSignUpForm(request.POST)
        if form.is_valid():
            try:
                user = form.save(commit=False)
                user.role = 'etudiant'
                user.is_active = False
                # Store user data in session instead of saving to DB
                request.session['pending_user'] = {
                    'username': user.username,
                    'email': user.email,
                    'password': form.cleaned_data['password1'],  # Store raw password securely in session
                    'role': user.role,
                    'is_active': user.is_active,
                }
                send_activation_email(user, request)
                messages.success(request, 'Activation email sent. Please check your email to activate your account.')
                return render(request, 'roles/signup.html', {'form': form})
            except Exception as e:
                logger.error(f"Unexpected error during signup: {e}")
                messages.error(request, 'Email could not be sent. Please try again.')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = DefaultSignUpForm()

    return render(request, 'roles/signup.html', {'form': form})

def activate_account(request, uidb64, token):
    """Activate user account via email token."""
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        # Check if session has pending user data
        pending_user = request.session.get('pending_user')
        if not pending_user:
            raise ValueError("No pending user data found.")
        user = User(
            username=pending_user['username'],
            email=pending_user['email'],
            role=pending_user['role'],
            is_active=pending_user['is_active']
        )
        user.set_password(pending_user['password'])  # Set password from session
    except (TypeError, ValueError, OverflowError):
        user = None
    if user and default_token_generator.check_token(user, token):
        messages.success(request, 'Account activated! Please sign in.')
        return redirect('roles:signin')
    else:
        messages.error(request, 'Invalid or expired activation link.')
        return redirect('roles:resend_activation')

def resend_activation(request):
    """Resend activation email."""
    if request.method == 'POST':
        form = ResendActivationForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            pending_user = request.session.get('pending_user')
            if pending_user and pending_user['email'] == email:
                user = User(
                    username=pending_user['username'],
                    email=pending_user['email'],
                    role=pending_user['role'],
                    is_active=pending_user['is_active']
                )
                user.set_password(pending_user['password'])
                try:
                    send_activation_email(user, request)
                    messages.success(request, 'Activation email resent. Check your email.')
                except Exception as e:
                    logger.error(f"Error resending activation: {e}")
                    messages.error(request, 'An error occurred. Please try again.')
            else:
                messages.error(request, 'No pending account found with this email.')
            return redirect('roles:signin')
    else:
        form = ResendActivationForm()
    return render(request, 'roles/resend_activation.html', {'form': form})

def signin(request):
    """Handle user login."""
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        pending_user = request.session.get('pending_user')
        if pending_user and pending_user['username'] == username:
            user = User(
                username=pending_user['username'],
                email=pending_user['email'],
                role=pending_user['role'],
                is_active=True  # Activate upon successful signin
            )
            user.set_password(pending_user['password'])
            if user.check_password(password):
                # Save the user to the database now
                try:
                    user.save()
                    Etudiant.objects.create(user=user)
                    login(request, user)
                    # Clear the session data after successful signin
                    del request.session['pending_user']
                    return redirect(user.get_redirect_url())
                except IntegrityError:
                    messages.error(request, 'Username or email already exists in the system.')
                except DatabaseError as e:
                    logger.error(f"Database error during signin: {e}")
                    messages.error(request, 'An error occurred. Please try again later.')
            else:
                messages.error(request, 'Invalid password.')
        else:
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



def logout_view(request):
    logout(request)
    return redirect('roles:signin')  # or wherever you want to go after logout