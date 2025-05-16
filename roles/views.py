from django.conf import settings
from django.http import HttpResponseRedirect
from django.template.loader import render_to_string
from django.core.exceptions import ValidationError
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.hashers import check_password
from django.contrib import messages
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode, base36_to_int
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator, PasswordResetTokenGenerator
from django.core.mail import send_mail
from django.db import IntegrityError, DatabaseError, transaction
from django.contrib.auth.decorators import login_required
from django.urls import reverse
import logging
import random
import datetime
from django.utils.crypto import constant_time_compare
import json
from django.core.serializers.json import DjangoJSONEncoder



from roles_project.settings import DEFAULT_FROM_EMAIL
from .models import Annee, Filiere, Niveau, Semestre, User, Invitation, Etudiant, Enseignant, Admin, ProfileEtudiant, Matiere, MatiereCommune
from .forms import DefaultSignUpForm, PinForm, ResendActivationForm, InvitationForm, StudentProfileForm

logger = logging.getLogger(__name__)

class ShortLivedTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            str(user.pk) + str(timestamp) +
            str(user.is_active) + str(user.email) +
            str(user.username)
        )
    def check_token(self, user, token):
        if not (user and token):
            return False
        try:
            ts_b36, _ = token.split("-")
            ts = base36_to_int(ts_b36)
        except ValueError:
            return False
        if (self._num_seconds(self._now()) - ts) > (15 * 60):  # 15 minutes
            return False
        return super().check_token(user, token)

short_lived_token_generator = ShortLivedTokenGenerator()

def send_activation_email(user_data, request):
    """Send an activation email with a 15-second token using session data."""
    token = short_lived_token_generator.make_token(user_data)  # Use custom token generator
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
            username = form.cleaned_data['username']
            if User.objects.filter(username=username).exists():
                messages.error(request, 'Username already exists')
                return render(request, 'roles/signup.html', {'form': form})
            try:
                with transaction.atomic():
                    user = form.save(commit=False)
                    user.role = 'etudiant'
                    user.is_active = False
                    user.set_password(form.cleaned_data['password1'])
                    user.save()

                    # Store pending user in session
                    pending_user = {
                        'username': user.username,
                        'email': user.email,
                        'first_name': user.first_name,
                        'last_name': user.last_name,
                        'role': user.role,
                        'password': user.password,  # Already hashed
                        'is_active': user.is_active
                    }
                    request.session['pending_user'] = pending_user
                    request.session.save()

                    # Generate activation token
                    uid = urlsafe_base64_encode(force_bytes(user.pk))
                    token = default_token_generator.make_token(user)
                    activation_link = request.build_absolute_uri(
                        reverse('roles:activate', kwargs={'uidb64': uid, 'token': token})
                    )

                    # Send activation email
                    send_mail(
                        'Activate Your Account',
                        f'Click the link to activate your account: {activation_link}',
                        settings.DEFAULT_FROM_EMAIL,
                        [user.email],
                        fail_silently=False,
                    )
                    messages.success(request, 'Activation email sent. Please check your email.')
                    return redirect('roles:signin')
            except Exception as e:
                logger.error(f"Error during signup: {e}")
                messages.error(request, 'An error occurred. Please try again later.')
                return render(request, 'roles/signup.html', {'form': form})
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = DefaultSignUpForm()

    return render(request, 'roles/signup.html', {'form': form})



def signin(request):
    """Handle user login."""
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        pending_user = request.session.get('pending_user')
        logger.debug(f"Signin attempt for {username}, pending_user: {pending_user}")

        if pending_user and pending_user['username'] == username:
            logger.debug(f"Checking password for pending user {username}")
            # Vérifier si un autre utilisateur existe déjà avec ce nom
            if User.objects.filter(username=username).exclude(email=pending_user['email']).exists():
                logger.error(f"Username {username} already exists for another user")
                messages.error(request, 'Username or email already exists.')
                return render(request, 'roles/signin.html', {'messages': messages.get_messages(request)})

            if check_password(password, pending_user['password']):
                try:
                    user = User(
                        username=pending_user['username'],
                        email=pending_user['email'],
                        first_name=pending_user['first_name'],
                        last_name=pending_user['last_name'],
                        role=pending_user['role'],
                        is_active=True
                    )
                    user.password = pending_user['password']
                    user.save()
                    if user.role == 'etudiant':
                        Etudiant.objects.create(user=user)
                    login(request, user)
                    del request.session['pending_user']
                    request.session.modified = True
                    logger.info(f"User {username} logged in, redirecting to etudiant_dashboard")
                    return HttpResponseRedirect(reverse('roles:etudiant_dashboard'))
                except IntegrityError:
                    logger.error(f"IntegrityError: Username {username} or email already exists")
                    messages.error(request, 'Username or email already exists.')
                except Exception as e:
                    logger.error(f"Error during signin: {e}")
                    messages.error(request, 'An error occurred. Please try again.')
            else:
                logger.error(f"Invalid password for pending user {username}")
                messages.error(request, 'Invalid password.')
        else:
            logger.debug(f"Checking non-pending user {username}")
            user = authenticate(request, username=username, password=password)
            if user:
                login(request, user)
                logger.info(f"User {username} logged in")
                if user.role == 'etudiant':
                    return HttpResponseRedirect(reverse('roles:etudiant_dashboard'))
                else:
                    messages.info(request, 'Login successful. Please proceed to your dashboard.')
                    return render(request, 'roles/signin.html', {'messages': messages.get_messages(request)})
            else:
                logger.error(f"Invalid username or password for {username}")
                messages.error(request, 'Invalid username or password.')

    logger.debug("Rendering signin.html")
    return render(request, 'roles/signin.html', {'messages': messages.get_messages(request)})



def activate_account(request, uidb64, token):
    """Activate user account via email token."""
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        pending_user = request.session.get('pending_user')
        if not pending_user:
            raise ValueError("No pending user data found.")
        user = User(
            username=pending_user['username'],
            email=pending_user['email'],
            first_name=pending_user['first_name'],
            last_name=pending_user['last_name'],
            role=pending_user['role'],
            is_active=pending_user['is_active']
        )
        user.password = pending_user['password']
    except (TypeError, ValueError, OverflowError) as e:
        user = None
        messages.error(request, f'Invalid activation link: {str(e)}')
        return redirect('roles:resend_activation')
    
    if user and short_lived_token_generator.check_token(user, token):
        user.is_active = True
        try:
            user.save()
            if user.role == 'etudiant':
                Etudiant.objects.create(user=user)
            del request.session['pending_user']
            messages.success(request, 'Account activated! Please sign in.')
            return redirect('roles:signin')
        except IntegrityError:
            logger.error(f"IntegrityError: User {user.username} already exists")
            messages.error(request, 'User already exists.')
            return redirect('roles:resend_activation')
    else:
        logger.error(f"Token check failed for user {user.username if user else 'None'}")
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
                    first_name=pending_user['first_name'],  # Include first_name
                    last_name=pending_user['last_name'],    # Include last_name
                    role=pending_user['role'],
                    is_active=pending_user['is_active']
                )
                user.password = pending_user['password']  # Set hashed password directly
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






# Etudiant creating his profile



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




 # Code for the creation of profiles
@login_required
def etudiant_dashboard(request):
    """Handle student dashboard and profile creation."""
    # Role check first to preserve original logic
    if request.user.role != 'etudiant':
        messages.error(request, 'Access denied.')
        return redirect('roles:signin')

    matiere_unavailable_message = None
    
    if request.method == 'POST':
        form = StudentProfileForm(request.POST)
        if form.is_valid():
            profile = form.save(commit=False)
            profile.etudiant = request.user.etudiant_profile
            profile.save()
            messages.success(request, 'Profile created successfully.')
            return redirect('roles:etudiant_dashboard')
        else:
            messages.error(request, 'Please correct the errors below.')
            # Check if matiere error is due to no available options
            if 'matiere' in form.errors and 'filiere' in form.data and 'semestre' in form.data and 'niveau' in form.data:
                try:
                    filiere_id = int(form.data.get('filiere'))
                    semestre_id = int(form.data.get('semestre'))
                    niveau_id = int(form.data.get('niveau'))
                    if not Matiere.objects.filter(
                        filiere_id=filiere_id, semestre_id=semestre_id, niveau_id=niveau_id
                    ).exists():
                        matiere_unavailable_message = "No subjects are available for the selected combination. You can still save your profile."
                except (ValueError, TypeError):
                    pass
    else:
        form = StudentProfileForm()

    # Fetch dropdown options directly from the database
    annee_choices = Annee.objects.all()
    niveau_choices = Niveau.objects.all()
    filiere_choices = Filiere.objects.all()
    semestre_choices = Semestre.objects.all()

    # Prepare data for dynamic subject filtering
    all_matieres = Matiere.objects.all().values('id', 'nom_matiere', 'filiere_id', 'semestre_id', 'niveau_id')
    matiere_data = {}
    for m in all_matieres:
        key = f"{m['filiere_id']}_{m['semestre_id']}_{m['niveau_id']}"
        if key not in matiere_data:
            matiere_data[key] = []
        matiere_data[key].append({'id': m['id'], 'nom': m['nom_matiere']})

    all_matieres_communes = MatiereCommune.objects.all().values('id', 'nom_matiere_commune', 'filiere_id', 'semestre_id', 'niveau_id')
    matiere_commune_data = {}
    for mc in all_matieres_communes:
        key = f"{mc['filiere_id']}_{mc['semestre_id']}_{mc['niveau_id']}"
        if key not in matiere_commune_data:
            matiere_commune_data[key] = []
        matiere_commune_data[key].append({'id': mc['id'], 'nom': mc['nom_matiere_commune']})

    context = {
        'form': form,
        'annee_choices': annee_choices,
        'niveau_choices': niveau_choices,
        'filiere_choices': filiere_choices,
        'semestre_choices': semestre_choices,
        'matiere_data': json.dumps(matiere_data, cls=DjangoJSONEncoder),
        'matiere_commune_data': json.dumps(matiere_commune_data, cls=DjangoJSONEncoder),
        'matiere_unavailable_message': matiere_unavailable_message,
    }
    return render(request, 'roles/etudiant_dashboard.html', context)