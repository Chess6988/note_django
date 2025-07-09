import pytest
import logging
from django.test import RequestFactory, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.contrib.messages.storage.fallback import FallbackStorage
from django.core import mail
from django.db import IntegrityError
from unittest.mock import patch, Mock
import time
from base64 import urlsafe_b64encode  # Fixed import
from django.utils.encoding import force_bytes
from roles.views import ShortLivedTokenGenerator, send_activation_email, etudiant_signup, signin, activate_account, resend_activation
from roles.forms import DefaultSignUpForm, ResendActivationForm
from roles.models import Etudiant
from django.contrib.messages import get_messages

User = get_user_model()

# Set up logging for tests
logger = logging.getLogger(__name__)

@pytest.fixture
def request_factory():
    return RequestFactory()

@pytest.fixture
def client():
    return Client()

@pytest.fixture
def user_data():
    return {
        'username': 'testuser',
        'email': 'testuser@example.com',
        'password1': 'SecurePass123!',
        'password2': 'SecurePass123!',
        'first_name': 'Test',
        'last_name': 'User'
    }

@pytest.fixture
def pending_user():
    user = User.objects.create(
        username='pendinguser',
        email='pendinguser@example.com',
        is_active=False,
        role='etudiant'
    )
    user.set_password('SecurePass123!')
    user.save()
    return user

@pytest.fixture
def active_user():
    user = User.objects.create(
        username='activeuser',
        email='activeuser@example.com',
        is_active=True,
        role='etudiant'
    )
    user.set_password('SecurePass123!')
    user.save()
    return user

@pytest.fixture
def token_generator():
    return ShortLivedTokenGenerator()

@pytest.mark.django_db
class TestShortLivedTokenGenerator:
    def test_make_token(self, pending_user, token_generator):
        """Test token generation for a user."""
        token = token_generator.make_token(pending_user)
        assert isinstance(token, str)
        assert len(token.split('-')) == 2

    def test_check_valid_token(self, pending_user, token_generator):
        """Test validating a valid token."""
        token = token_generator.make_token(pending_user)
        assert token_generator.check_token(pending_user, token) is True

    def test_check_expired_token(self, pending_user, token_generator):
        """Test validating an expired token."""
        token = token_generator.make_token(pending_user)
        # Patch _now to simulate time far in the future so token is expired
        from datetime import datetime, timedelta
        fake_now = token_generator._now()
        if isinstance(fake_now, datetime):
            # If _now returns datetime, add timedelta
            future = fake_now + timedelta(seconds=3600)
        else:
            # If _now returns int (timestamp), add seconds
            future = fake_now + 3600
        with patch.object(token_generator, '_now', return_value=future):
            assert token_generator.check_token(pending_user, token) is False

    def test_check_invalid_token(self, pending_user, token_generator):
        """Test validating an invalid token format."""
        assert token_generator.check_token(pending_user, 'invalid-token') is False

    def test_check_missing_user_or_token(self, pending_user, token_generator):
        """Test validation with missing user or token."""
        assert token_generator.check_token(None, 'some-token') is False
        assert token_generator.check_token(pending_user, None) is False

@pytest.mark.django_db
def test_send_activation_email_success(request_factory, pending_user):
    from roles.views import send_activation_email
    request = request_factory.get('/')
    request.build_absolute_uri = Mock(return_value='http://example.com/activate/uid/token')
    # Patch send_mail in the correct module where it is used (roles.views)
    with patch('roles.views.send_mail') as mock_send_mail, \
         patch('django.template.loader.render_to_string', return_value='Email content'):
        mock_send_mail.return_value = 1
        send_activation_email(pending_user, request)
        assert mock_send_mail.called

@pytest.mark.django_db
def test_signup_post_valid_form(client, user_data):
    from unittest.mock import patch
    with patch('django.core.mail.send_mail'), \
         patch('django.template.loader.render_to_string', return_value='Email content'):
        response = client.post(reverse('roles:etudiant_signup'), user_data)
        assert response.status_code == 200
        # Use get_messages to check for the message
        messages_list = list(get_messages(response.wsgi_request))
        assert any('Activation email sent' in msg.message for msg in messages_list)

@pytest.mark.django_db
def test_signup_email_already_exists(client, user_data, pending_user):
    user_data['email'] = pending_user.email
    response = client.post(reverse('roles:etudiant_signup'), user_data)
    assert response.status_code == 200
    # Accept either message variant
    messages_list = list(get_messages(response.wsgi_request))
    assert any('This email is already registered' in msg.message or 'A user with this email already exists.' in msg.message for msg in messages_list)

@pytest.mark.django_db
def test_send_activation_email_failure(request_factory, pending_user):
    from roles.views import send_activation_email
    request = request_factory.get('/')
    request.build_absolute_uri = Mock(return_value='http://example.com/activate/uid/token')
    # Patch send_mail in the correct module where it is used (roles.views)
    with patch('roles.views.send_mail', side_effect=Exception('SMTP error')):
        with pytest.raises(Exception, match='SMTP error'):
            send_activation_email(pending_user, request)

@pytest.mark.django_db
def test_signup_get_request(client):
    response = client.get(reverse('roles:etudiant_signup'))
    assert response.status_code == 200
    assert 'form' in response.context
    assert isinstance(response.context['form'], DefaultSignUpForm)

@pytest.mark.django_db
def test_signup_post_invalid_form(client):
    response = client.post(reverse('roles:etudiant_signup'), {'username': '', 'email': ''})
    assert response.status_code == 200
    assert any('error' in msg.tags for msg in response.context['messages'])

@pytest.mark.django_db
class TestSignin:
    def test_signin_get_request(self, client):
        response = client.get(reverse('roles:signin'))
        assert response.status_code == 200
        assert 'roles/signin.html' in [t.name for t in response.templates]  # Changed from 'signin.html'

    def test_signin_post_valid_credentials(self, client, active_user):
        """Test POST request with valid credentials."""
        response = client.post(reverse('roles:signin'), {
            'username': active_user.username,
            'password': 'SecurePass123!'
        })
        assert response.status_code == 302
        assert response.url == reverse('roles:etudiant_dashboard')

    def test_signin_post_invalid_credentials(self, client):
         response = client.post(reverse('roles:signin'), {
        'username': 'nonexistent',
        'password': 'wrongpass'
    })
         assert response.status_code == 200
         assert 'Invalid username or password.' in [msg.message for msg in response.context['messages']]  # Added period

    def test_signin_pending_user(self, client, pending_user):
         response = client.post(reverse('roles:signin'), {
        'username': pending_user.username,
        'password': 'SecurePass123!'
    })
         assert response.status_code == 200
         assert 'Please activate your account first.' in [msg.message for msg in response.context['messages']]  # Added period

@pytest.mark.django_db
class TestActivateAccount:
    def test_activate_account_valid_token(self, client, pending_user, token_generator):
       token = token_generator.make_token(pending_user)
       uid = urlsafe_b64encode(force_bytes(pending_user.pk)).decode()  # Convert bytes to string
       response = client.get(reverse('roles:activate', kwargs={'uidb64': uid, 'token': token}))
       assert response.status_code == 302
       assert response.url == reverse('roles:signin')
       pending_user.refresh_from_db()
       assert pending_user.is_active
       assert Etudiant.objects.filter(user=pending_user).exists()

    def test_activate_account_invalid_token(self, client, pending_user):
    
       uid = urlsafe_b64encode(force_bytes(pending_user.pk)).decode()
       response = client.get(reverse('roles:activate', kwargs={'uidb64': uid, 'token': 'invalid-token'}), follow=True)
       assert response.status_code == 200  # Assuming the redirect leads to a rendered page
       messages_list = list(get_messages(response.wsgi_request))
       assert any('Invalid or expired activation link' in msg.message for msg in messages_list)
@pytest.mark.django_db
class TestResendActivation:
    def test_resend_activation_get_request(self, client):
        """Test GET request for resend activation page."""
        response = client.get(reverse('roles:resend_activation'))
        assert response.status_code == 200
        assert 'form' in response.context
        assert isinstance(response.context['form'], ResendActivationForm)

    def test_resend_activation_post_valid_email(self, client, pending_user):
        """Test POST request for resending activation email."""
        from unittest.mock import patch
        client.session['pending_user'] = {
            'username': pending_user.username,
            'email': pending_user.email,
            'pk': pending_user.pk,
            'role': pending_user.role,
            'is_active': pending_user.is_active
        }
        client.session.save()
        with patch('django.core.mail.send_mail'), \
             patch('django.template.loader.render_to_string', return_value='Email content'):
            response = client.post(reverse('roles:resend_activation'), {'email': pending_user.email})
            assert response.status_code == 302
            assert response.url == reverse('roles:signin')
            # ...assert message...

    def test_resend_activation_post_invalid_email(self, client):
        response = client.post(reverse('roles:resend_activation'), {'email': 'nonexistent@example.com'})
        assert response.status_code == 200
        assert 'No pending account found with this email.' in [msg.message for msg in response.context['messages']]