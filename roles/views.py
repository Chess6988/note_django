from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.template.loader import render_to_string
from django.core.exceptions import ValidationError
from django.shortcuts import render, redirect, get_object_or_404
from django.db import transaction
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
from django.db.models import Q
from django.forms import formset_factory
from django.utils.http import base36_to_int


from roles_project.settings import DEFAULT_FROM_EMAIL
from .models import Annee, Filiere, MatiereCommuneEtudiant, MatiereEtudiant, Niveau, Semestre, User, Invitation, Etudiant, Enseignant, Admin, ProfileEtudiant, Matiere, MatiereCommune
from .forms import DefaultSignUpForm, PinForm, ResendActivationForm, InvitationForm, StudentProfileForm

logger = logging.getLogger(__name__)

# ShortLivedTokenGenerator remains unchanged


# End of activate_account view
# Start of verify_invitation view


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



def fetch_profiles(request):
    profiles = ProfileEtudiant.objects.filter(etudiant=request.user.etudiant_profile)
    return HttpResponse(render_to_string('roles/profiles_partial.html', {'profiles': profiles}))

# Start etudiant_dashboard view





@login_required
def etudiant_dashboard(request):
    """Handle student dashboard and profile creation."""
    if request.user.role != 'etudiant':
        messages.error(request, 'Access denied.')
        return redirect('roles:signin')

    StudentProfileFormSet = formset_factory(StudentProfileForm, extra=1)
    context = _prepare_context()

    if request.method == 'POST':
        return _handle_post_request(request, StudentProfileFormSet, context)
    
    context['formset'] = StudentProfileFormSet()
    return render(request, 'roles/etudiant_dashboard.html', context)

def fetch_subjects(request):
    """Fetch subjects via AJAX based on filiere, semestre, and niveau."""
    filiere_id = request.GET.get('filiere')
    semestre_id = request.GET.get('semestre')
    niveau_id = request.GET.get('niveau')

    matieres = _fetch_matieres(filiere_id, semestre_id, niveau_id)
    matieres_communes = _fetch_matieres_communes(semestre_id, niveau_id)

    return JsonResponse({
        'matieres': list(matieres),
        'matieres_communes': list(matieres_communes),
    })

def _prepare_context():
    """Prepare context data for the dashboard template."""
    return {
        'annee_choices': Annee.objects.all(),
        'niveau_choices': Niveau.objects.all(),
        'filiere_choices': Filiere.objects.all(),
        'semestre_choices': Semestre.objects.all(),
        'matiere_unavailable_message': None,
    }

def _handle_post_request(request, StudentProfileFormSet, context):
    """Process POST request for profile creation."""
    formset = StudentProfileFormSet(request.POST)
    context['formset'] = formset

    _check_subjects_availability(request, formset, context)
    if context.get('matiere_unavailable_message'):
        return render(request, 'roles/etudiant_dashboard.html', context)
    
    if not formset.is_valid():
        messages.error(request, 'Please correct the errors below.')
        return render(request, 'roles/etudiant_dashboard.html', context)
        
    try:
        with transaction.atomic():
            for form in formset:
                if not form.cleaned_data:
                    continue
                existing = ProfileEtudiant.objects.filter(
                    etudiant=request.user.etudiant_profile,
                    annee=form.cleaned_data['annee'],
                    niveau=form.cleaned_data['niveau'],
                    filiere=form.cleaned_data['filiere'],
                    semestre=form.cleaned_data['semestre']
                ).exists()
                if existing:
                    messages.error(request, 'A profile with this combination already exists.')
                    return render(request, 'roles/etudiant_dashboard.html', context)
                profile = form.save(commit=False)
                profile.etudiant = request.user.etudiant_profile
                profile.save()
                if form.cleaned_data.get('matiere'):
                    MatiereEtudiant.objects.create(
                        etudiant=profile.etudiant,
                        matiere=form.cleaned_data['matiere']
                    )
                if form.cleaned_data.get('matiere_commune'):
                    MatiereCommuneEtudiant.objects.create(
                        etudiant=profile.etudiant,
                        matiere_commune=form.cleaned_data['matiere_commune']
                    )
            messages.success(request, 'Profile created successfully.')
            return redirect('roles:etudiant_dashboard')
    except Exception as e:
        logger.error(f"Error creating profile: {str(e)}")
        messages.error(request, 'An error occurred while creating the profile.')
        return render(request, 'roles/etudiant_dashboard.html', context)

def _check_subjects_availability(request, formset, context):
    """Check if subjects are available for the submitted combination."""
    required_keys = ['form-0-filiere', 'form-0-semestre', 'form-0-niveau']
    if all(key in formset.data for key in required_keys):
        try:
            filiere_id = formset.data.get('form-0-filiere')
            semestre_id = formset.data.get('form-0-semestre')
            niveau_id = formset.data.get('form-0-niveau')
            has_subjects = Matiere.objects.filter(
                filiere_id=filiere_id,
                semestre_id=semestre_id,
                niveau_id=niveau_id
            ).exists()
            if not has_subjects:
                context['matiere_unavailable_message'] = "No subjects are available for this combination"
                messages.warning(request, context['matiere_unavailable_message'])
        except (ValueError, TypeError):
            pass



def _fetch_matieres(filiere_id, semestre_id, niveau_id):
    """Fetch matieres based on filiere, semestre, and niveau."""
    return Matiere.objects.filter(
        filiere_id=filiere_id,
        semestre_id=semestre_id,
        niveau_id=niveau_id
    ).values('id', 'nom_matiere')

def _fetch_matieres_communes(semestre_id, niveau_id):
    """Fetch common subjects based on semestre and niveau."""
    return MatiereCommune.objects.filter(
        filiere=None,
        semestre_id=semestre_id,
        niveau_id=niveau_id
    ).values('id', 'nom_matiere_commune')

class ShortLivedTokenGenerator(PasswordResetTokenGenerator):
    """Token generator for 15-minute activation tokens."""
    TOKEN_LIFETIME = 15 * 60  # 15 minutes in seconds

    def _make_hash_value(self, user, timestamp):
        """Create a unique hash value for the user."""
        return (
            str(user.pk) + str(timestamp) +
            str(user.is_active) + str(user.email) +
            str(user.username)
        )
    
    def check_token(self, user, token):
        """
        Validate the token with additional time expiration check.
        Returns False if:
        - User or token is missing
        - Token format is invalid
        - Token is expired (>15 minutes)
        - Token doesn't match the user's data
        """
        if not (user and token):
            logger.debug("Missing user or token")
            return False

        try:
            ts_b36, _ = token.split("-")
            ts = base36_to_int(ts_b36)
            if (self._num_seconds(self._now()) - ts) > self.TOKEN_LIFETIME:
                logger.debug(f"Token expired for user {user.username}")
                return False
        except (ValueError, TypeError) as e:
            logger.error(f"Token validation error for user {user.username}: {str(e)}")
            return False

        return super().check_token(user, token)

short_lived_token_generator = ShortLivedTokenGenerator()

def send_activation_email(user_data, request):
    """
    Send an activation email with a 15-minute token using session data.
    
    Args:
        user_data: User instance with required fields (pk, email)
        request: HttpRequest instance for building absolute URI
        
    Raises:
        SMTPException: If email sending fails
    """
    try:
        token = short_lived_token_generator.make_token(user_data)
        uid = urlsafe_base64_encode(force_bytes(user_data.pk))
        activation_link = request.build_absolute_uri(
            reverse('roles:activate', kwargs={'uidb64': uid, 'token': token})
        )
        subject = "Activate Your Account"
        message = render_to_string('activation_email.html', {
            'user': user_data,
            'activation_link': activation_link,
        })
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user_data.email],
            html_message=message,
            fail_silently=False
        )
        logger.info(f"Activation email sent successfully to {user_data.email}")
    except Exception as e:
        logger.error(f"Failed to send activation email to {user_data.email}: {e}")
        raise

def etudiant_signup(request):
    """Handle Etudiant self-registration."""
    if request.user.is_authenticated and request.user.role == 'etudiant':
        return redirect(request.user.get_redirect_url())

    form = DefaultSignUpForm(request.POST or None)
    
    if request.method == 'POST':
        context = {'form': form}
        return _handle_post_request_signup(request, form, context)
    
    return render(request, 'roles/signup.html', {'form': form})

def _handle_post_request_signup(request, form, context):
    """Process POST request for signup."""
    if not form.is_valid():
        if 'username' in form.errors and any(
            "A user with that username already exists." in err for err in form.errors['username']
        ):
            messages.error(request, 'Username already exists')
        else:
            messages.error(request, 'Please correct the errors below.')
        return render(request, 'roles/signup.html', context)
    
    username = form.cleaned_data['username']
    if User.objects.filter(username=username).exists():
        form.add_error('username', 'Username already exists')
        messages.error(request, 'Username already exists')
        return render(request, 'roles/signup.html', context)

    try:
        user = _create_pending_user(form)
        _store_pending_user_in_session(request, user)
        send_activation_email(user, request)
        messages.success(request, 'Activation email sent. Please check your email.')
        return redirect('roles:signin')
    except Exception as e:
        logger.error(f"Error during signup: {e}")
        messages.error(request, 'An error occurred. Please try again later.')
        return render(request, 'roles/signup.html', context)
    
def _create_pending_user(form):
    """Create and save a pending user with atomic transaction."""
    with transaction.atomic():
        user = form.save(commit=False)
        user.role = 'etudiant'
        user.is_active = False
        user.set_password(form.cleaned_data['password1'])
        user.save()
    return user

def _store_pending_user_in_session(request, user):
    """Store pending user details in session."""
    pending_user = {
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'role': user.role,
        'password': user.password,
        'is_active': user.is_active,
        'pk': user.pk
    }
    request.session['pending_user'] = pending_user
    request.session.save()

def signin(request):
    """Handle user login."""
    if request.method == 'POST':
        return _handle_post_request_signin(request)
    
    logger.debug("Rendering signin.html")
    return render(request, 'roles/signin.html', {'messages': messages.get_messages(request)})

def _handle_post_request_signin(request):
    username = request.POST.get('username')
    password = request.POST.get('password')
    pending_user = request.session.get('pending_user')
    logger.debug(f"Session keys: {list(request.session.keys())}")
    logger.debug(f"Signin attempt for {username}, pending_user: {pending_user}")
    try:
        user = User.objects.get(username=username)
        if not user.is_active:
            if pending_user and pending_user['username'] == username:
                return _handle_pending_user(request, username, password, pending_user)
            messages.error(request, 'Please activate your account first.')
            return render(request, 'roles/signin.html')
        return _handle_existing_user(request, username, password)
    except User.DoesNotExist:
        messages.error(request, 'Invalid username or password.')
        return render(request, 'roles/signin.html')
    except IntegrityError:
        messages.error(request, 'Username or email already exists.')
        logger.debug(f"Checking password for pending user {username}")
        
        try:
            user = User.objects.get(username=username)
            if not user.check_password(password):
                logger.error(f"Invalid password for pending user {username}")
                messages.error(request, 'Invalid password.')
                return render(request, 'roles/signin.html', {'messages': messages.get_messages(request)})
            # Activate the user
            user.is_active = True
            user.save()
            _finalize_user_setup(request, user)
            logger.info(f"User {username} logged in, redirecting to etudiant_dashboard")
            return HttpResponseRedirect(reverse('roles:etudiant_dashboard'))
        except User.DoesNotExist:
            logger.error(f"User {username} not found")
            messages.error(request, 'User not found.')
            return render(request, 'roles/signin.html', {'messages': messages.get_messages(request)})
        except IntegrityError:
            logger.error(f"IntegrityError: Username {username} or email already exists")
            messages.error(request, 'Username or email already exists.')
            return render(request, 'roles/signin.html', {'messages': messages.get_messages(request)})
        except Exception as e:
            logger.error(f"Error during signin: {e}")
            messages.error(request, 'An error occurred. Please try again.')
            return render(request, 'roles/signin.html', {'messages': messages.get_messages(request)})

def _handle_pending_user(request, username, password, pending_user):
    """Process signin for a pending user."""
    try:
        user = User.objects.get(username=username)
        if not user.check_password(password):
            messages.error(request, 'Invalid password.')
            return render(request, 'roles/signin.html')
        
        with transaction.atomic():
            user.is_active = True
            user.save()
            if user.role == 'etudiant' and not Etudiant.objects.filter(user=user).exists():
                Etudiant.objects.create(user=user)
            login(request, user)
            if 'pending_user' in request.session:
                del request.session['pending_user']
            return redirect('roles:etudiant_dashboard')
    except Exception as e:
        logger.error(f"Error in pending user signin: {e}")
        messages.error(request, 'An error occurred. Please try again.')
        return render(request, 'roles/signin.html')

def _handle_existing_user(request, username, password):
    """Process signin for an existing user."""
    user = authenticate(request, username=username, password=password)
    
    if not user:
        messages.error(request, 'Invalid username or password.')
        return render(request, 'roles/signin.html')

    login(request, user)
    return redirect('roles:etudiant_dashboard') if user.role == 'etudiant' else redirect('roles:signin')

def _create_active_user(pending_user):
    """Retrieve and activate existing user from pending user data."""
    user = User.objects.get(pk=pending_user['pk'])  # Changed to retrieve existing user
    user.is_active = True
    user.save()
    return user

def _finalize_user_setup(request, user):
    """Complete user setup, including Etudiant creation and session cleanup."""
    if user.role == 'etudiant' and not Etudiant.objects.filter(user=user).exists():
        Etudiant.objects.create(user=user)
    login(request, user)
    if 'pending_user' in request.session:
        del request.session['pending_user']
        request.session.modified = True
        

def activate_account(request, uidb64, token):
    """Activate user account via email token."""
    try:
        user = _get_user_from_session_and_uid(request, uidb64)
        if not short_lived_token_generator.check_token(user, token):
            logger.error(f"Token check failed for user {user.username}")
            messages.error(request, 'Invalid or expired activation link.')
            return redirect('roles:resend_activation')

        return _activate_user(request, user)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist) as e:
        logger.error(f"Invalid activation link: {str(e)}")
        messages.error(request, 'Invalid activation link.')
        return redirect('roles:resend_activation')

def _get_user_from_session_and_uid(request, uidb64):
    """Retrieve user from session and decoded UID."""
    pending_user = request.session.get('pending_user')
    if not pending_user:
        raise ValueError("No pending user data found.")
    return User.objects.get(pk=pending_user['pk'])

def _activate_user(request, user):
    """Activate user, create Etudiant if needed, and clean up session."""
    if user.is_active:
        messages.error(request, 'Account is already activated.')
        return redirect('roles:signin')
    
    try:
        with transaction.atomic():
            user.is_active = True
            user.save()
            if user.role == 'etudiant' and not Etudiant.objects.filter(user=user).exists():
                Etudiant.objects.create(user=user)
            if 'pending_user' in request.session:
                del request.session['pending_user']
            messages.success(request, 'Account activated! Please sign in.')
            return redirect('roles:signin')
    except Exception as e:
        logger.error(f"Error during activation for user {user.username}: {str(e)}")
        messages.error(request, 'An error occurred during activation.')
        return redirect('roles:signin')

def resend_activation(request):
    """Resend activation email."""
    if request.method == 'POST':
        return _handle_resend_post_request(request)
    
    form = ResendActivationForm()
    return render(request, 'roles/resend_activation.html', {'form': form})

def _handle_resend_post_request(request):
    """Process POST request for resending activation email."""
    form = ResendActivationForm(request.POST)
    if not form.is_valid():
        messages.error(request, 'Please correct the errors below.')
        return render(request, 'roles/resend_activation.html', {'form': form})

    email = form.cleaned_data['email']
    try:
        # First check if there's a pending user in session
        pending_user = request.session.get('pending_user')
        if pending_user and pending_user['email'] == email:
            user = User.objects.get(pk=pending_user['pk'])
        else:
            # If not in session, try to find an inactive user with this email
            user = User.objects.get(email=email, is_active=False)
            # Store user data in session for activation
            _store_pending_user_in_session(request, user)
        
        if user.is_active:
            messages.info(request, 'This account is already active. Please sign in.')
            return redirect('roles:signin')
            
        send_activation_email(user, request)
        messages.success(request, 'Activation email sent. Please check your email.')
        return redirect('roles:signin')
    except User.DoesNotExist:
        messages.error(request, 'No pending account found with this email.')
    except Exception as e:
        logger.error(f"Error resending activation: {e}")
        messages.error(request, 'An error occurred. Please try again.')
    return render(request, 'roles/resend_activation.html', {'form': form})

def _create_user_from_pending(pending_user):
    """Retrieve existing User instance from pending user data."""
    return User.objects.get(pk=pending_user['pk'])