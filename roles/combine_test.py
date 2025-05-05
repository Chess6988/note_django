import pytest
from django.test import Client
from django.urls import reverse
from django.utils import timezone
from django.db import IntegrityError
from django.contrib.auth.hashers import make_password, check_password
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from datetime import timedelta
import uuid
from django.core.exceptions import ValidationError

from roles.models import User, Invitation, Etudiant, Enseignant, Admin
from roles.forms import DefaultSignUpForm, PinForm, ResendActivationForm, InvitationForm
from roles.views import short_lived_token_generator

# Fixtures
@pytest.fixture
def client():
    """Create a test client for making HTTP requests."""
    return Client()

@pytest.fixture
def superadmin_user():
    """Create a superadmin user for testing."""
    return User.objects.create_superuser(username='superadmin', email='superadmin@example.com', password='password', role='superadmin')

@pytest.fixture
def admin_user():
    """Create an admin user for testing."""
    return User.objects.create_user(username='admin', email='admin@example.com', password='password', role='admin')

@pytest.fixture
def enseignant_user():
    """Create an enseignant user for testing."""
    return User.objects.create_user(username='enseignant', email='enseignant@example.com', password='password', role='enseignant')

@pytest.fixture
def etudiant_user():
    """Create an etudiant user for testing."""
    return User.objects.create_user(username='etudiant', email='etudiant@example.com', password='password', role='etudiant')

@pytest.fixture
def invitation(superadmin_user):
    """Create a pending invitation for testing."""
    invitation = Invitation.objects.create(
        role='enseignant',
        email='invited@example.com',
        inviter=superadmin_user,
        expires_at=timezone.now() + timedelta(hours=24)
    )
    invitation.set_pin('123456')  # Use set_pin to ensure PIN is hashed and saved
    return invitation

# Model Tests
@pytest.mark.django_db
class TestModels:
    def test_user_creation(self):
        """Test creating a user with different roles."""
        user = User.objects.create_user(username='testuser', email='test@example.com', password='password', role='etudiant')
        assert user.username == 'testuser'
        assert user.email == 'test@example.com'
        assert user.role == 'etudiant'
        assert user.check_password('password')

    def test_invitation_creation(self, superadmin_user):
        """Test creating an invitation with PIN and expiration."""
        invitation = Invitation.objects.create(
            role='enseignant',
            email='invited@example.com',
            inviter=superadmin_user,
            expires_at=timezone.now() + timedelta(hours=24)
        )
        invitation.set_pin('123456')
        assert invitation.role == 'enseignant'
        assert invitation.check_pin('123456')
        assert not invitation.is_expired()

    def test_invitation_expiration(self, superadmin_user):
        """Test that an invitation expires correctly."""
        invitation = Invitation.objects.create(
            role='enseignant',
            email='invited@example.com',
            inviter=superadmin_user,
            expires_at=timezone.now() - timedelta(hours=1)
        )
        assert invitation.is_expired()

    def test_invitation_pin_validation(self, superadmin_user):
        """Test PIN validation for invitations."""
        invitation = Invitation.objects.create(
            role='enseignant',
            email='invited@example.com',
            inviter=superadmin_user,
            expires_at=timezone.now() + timedelta(hours=24)
        )
        with pytest.raises(ValidationError):
            invitation.set_pin('123')  # Too short

# Form Tests
@pytest.mark.django_db
class TestForms:
    def test_default_signup_form_valid(self):
        """Test DefaultSignUpForm with valid data."""
        form_data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'first_name': 'New',
            'last_name': 'User',
            'password1': 'complexpassword123',
            'password2': 'complexpassword123'
        }
        form = DefaultSignUpForm(data=form_data)
        assert form.is_valid()

    def test_default_signup_form_invalid(self):
        """Test DefaultSignUpForm with invalid data."""
        form_data = {
            'username': 'newuser',
            'email': 'invalidemail',
            'first_name': 'New',
            'last_name': 'User',
            'password1': 'complexpassword123',
            'password2': 'differentpassword'
        }
        form = DefaultSignUpForm(data=form_data)
        assert not form.is_valid()
        assert 'email' in form.errors
        assert 'password2' in form.errors

    def test_pin_form_valid(self):
        """Test PinForm with valid PIN."""
        form_data = {'pin': '123456'}
        form = PinForm(data=form_data)
        assert form.is_valid()

    def test_pin_form_invalid(self):
        """Test PinForm with invalid PIN."""
        form_data = {'pin': '12345'}  # Less than 6 digits
        form = PinForm(data=form_data)
        assert not form.is_valid()
        assert 'pin' in form.errors

    def test_resend_activation_form_valid(self):
        """Test ResendActivationForm with valid email."""
        form_data = {'email': 'user@example.com'}
        form = ResendActivationForm(data=form_data)
        assert form.is_valid()

    def test_invitation_form_invalid_role(self):
        """Test InvitationForm with invalid role (etudiant)."""
        form_data = {'role': 'etudiant', 'email': 'invited@example.com'}
        form = InvitationForm(data=form_data)
        assert not form.is_valid()
        assert 'role' in form.errors

# View Tests
@pytest.mark.django_db
class TestViews:
    def test_etudiant_signup_get(self, client):
        """Test GET request to etudiant_signup renders the form."""
        response = client.get(reverse('roles:etudiant_signup'))
        assert response.status_code == 200
        assert 'form' in response.context

    def test_etudiant_signup_post_valid(self, client, mocker):
        """Test POST request to etudiant_signup with valid data."""
        mocker.patch('roles.views.send_activation_email')
        form_data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'first_name': 'New',
            'last_name': 'User',
            'password1': 'complexpassword123',
            'password2': 'complexpassword123'
        }
        response = client.post(reverse('roles:etudiant_signup'), data=form_data)
        assert response.status_code == 302 

    def test_etudiant_signup_authenticated(self, client, etudiant_user):
        """Test etudiant_signup redirects authenticated etudiant."""
        client.login(username='etudiant', password='password')
        response = client.get(reverse('roles:etudiant_signup'))
        assert response.status_code == 302
        assert response.url == reverse('roles:etudiant_dashboard')

    def test_activate_account_valid(self, client, mocker):
        """Test activating account with valid token."""
        # Clean up to prevent IntegrityError
        User.objects.filter(username='newuser').delete()
        User.objects.filter(email='newuser@example.com').delete()
        pending_user = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'first_name': 'New',
            'last_name': 'User',
            'password': make_password('complexpassword123'),
            'role': 'etudiant',
            'is_active': False
        }
        # Set session data
        session = client.session
        session['pending_user'] = pending_user
        session.save()
        assert 'pending_user' in client.session  # Verify session setup
        user = User(
            username=pending_user['username'],
            email=pending_user['email'],
            role=pending_user['role'],
            first_name=pending_user['first_name'],
            last_name=pending_user['last_name'],
            password=pending_user['password']
        )
        mocker.patch('roles.views.short_lived_token_generator.check_token', return_value=True)
        # Use a valid base64-encoded uid
        uid = urlsafe_base64_encode(force_bytes('dummy'))
        token = 'valid-token'  # Simplified for testing
        response = client.get(reverse('roles:activate', kwargs={'uidb64': uid, 'token': token}))
        assert response.status_code == 302
        assert response.url == reverse('roles:signin')
        # Additional assertions for robustness
        assert User.objects.filter(username='newuser', is_active=True).exists()
        assert Etudiant.objects.filter(user__username='newuser').exists()

    def test_activate_account_invalid(self, client):
        """Test activating account with invalid token."""
        response = client.get(reverse('roles:activate', kwargs={'uidb64': 'invalid', 'token': 'invalid'}))
        assert response.status_code == 302
        assert response.url == reverse('roles:resend_activation')

    def test_resend_activation_valid(self, client, mocker):
        """Test resending activation email with valid data."""
        mocker.patch('roles.views.send_activation_email')
        pending_user = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'first_name': 'New',
            'last_name': 'User',
            'password': make_password('complexpassword123'),
            'role': 'etudiant',
            'is_active': False
        }
        # Set session data
        session = client.session
        session['pending_user'] = pending_user
        session.save()
        assert 'pending_user' in client.session  # Verify session setup
        form_data = {'email': 'newuser@example.com'}
        response = client.post(reverse('roles:resend_activation'), data=form_data)
        assert response.status_code == 302
        assert response.url == reverse('roles:signin')

    def test_signin_pending_user(self, client):
        """Test signin with pending user data."""
        # Clean up to prevent IntegrityError
        User.objects.filter(username='newuser').delete()
        User.objects.filter(email='newuser@example.com').delete()
        pending_user = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'first_name': 'New',
            'last_name': 'User',
            'password': make_password('complexpassword123'),
            'role': 'etudiant',
            'is_active': False
        }
        # Set session data
        session = client.session
        session['pending_user'] = pending_user
        session.save()
        assert 'pending_user' in client.session  # Verify session setup
        form_data = {
            'username': 'newuser',
            'password': 'complexpassword123'
        }
        response = client.post(reverse('roles:signin'), data=form_data)
        assert response.status_code == 302
        assert response.url == reverse('roles:etudiant_dashboard')
        assert User.objects.filter(username='newuser').exists()
        assert Etudiant.objects.filter(user__username='newuser').exists()

    def test_verify_invitation_valid_pin(self, client, invitation):
        """Test verifying invitation with valid PIN."""
        form_data = {'pin': '123456'}
        response = client.post(reverse('roles:verify_invitation', args=[str(invitation.token)]), data=form_data)
        assert response.status_code == 302
        assert response.url == reverse('roles:invited_signup', args=[str(invitation.token)])

    def test_verify_invitation_exceeded_attempts(self, client, invitation):
        """Test verifying invitation after exceeding attempts."""
        invitation.attempt_count = 3
        invitation.save()
        response = client.get(reverse('roles:verify_invitation', args=[str(invitation.token)]))
        assert response.status_code == 302
        assert response.url == reverse('roles:signin')

    def test_invited_signup_valid(self, client, invitation, mocker):
        """Test invited signup with valid data."""
        mocker.patch('roles.views.send_activation_email')
        form_data = {
            'username': 'inviteduser',
            'email': invitation.email,
            'first_name': 'Invited',
            'last_name': 'User',
            'password1': 'complexpassword123',
            'password2': 'complexpassword123'
        }
        response = client.post(reverse('roles:invited_signup', args=[str(invitation.token)]), data=form_data)
        assert response.status_code == 302
        assert response.url == reverse('roles:signin')
        assert User.objects.filter(username='inviteduser', role='enseignant').exists()
        assert Enseignant.objects.filter(user__username='inviteduser').exists()

    def test_send_invitation_superadmin(self, client, superadmin_user):
        """Test sending invitation as superadmin."""
        client.login(username='superadmin', password='password')
        form_data = {'role': 'enseignant', 'email': 'newinvite@example.com'}
        response = client.post(reverse('roles:send_invitation'), data=form_data)
        assert response.status_code == 302
        assert Invitation.objects.filter(email='newinvite@example.com').exists()

    def test_send_invitation_permission_denied(self, client, etudiant_user):
        """Test sending invitation without permission."""
        client.login(username='etudiant', password='password')
        response = client.get(reverse('roles:send_invitation'))
        assert response.status_code == 302
        assert response.url == reverse('roles:signin')

    def test_etudiant_dashboard_access(self, client, etudiant_user):
        """Test etudiant dashboard access for correct role."""
        client.login(username='etudiant', password='password')
        response = client.get(reverse('roles:etudiant_dashboard'))
        assert response.status_code == 200

    def test_etudiant_dashboard_access_denied(self, client, enseignant_user):
        """Test etudiant dashboard access denied for wrong role."""
        client.login(username='enseignant', password='password')
        response = client.get(reverse('roles:etudiant_dashboard'))
        assert response.status_code == 302
        assert response.url == reverse('roles:signin')

    def test_logout(self, client, etudiant_user):
        """Test logout functionality."""
        client.login(username='etudiant', password='password')
        response = client.get(reverse('roles:logout'))
        assert response.status_code == 302
        assert response.url == reverse('roles:signin')
        assert '_auth_user_id' not in client.session