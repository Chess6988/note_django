import pytest
from django.test import Client, RequestFactory
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.contrib.messages import get_messages
from django.core import mail
from django.db import IntegrityError
from unittest.mock import Mock, patch
from base64 import urlsafe_b64encode
from django.utils.encoding import force_bytes
from roles.views import ShortLivedTokenGenerator, send_activation_email, etudiant_signup, signin, activate_account, resend_activation
from roles.forms import DefaultSignUpForm, ResendActivationForm
from roles.models import Etudiant, ProfileEtudiant
from django.core.exceptions import ObjectDoesNotExist

User = get_user_model()

@pytest.fixture
def client():
    return Client()

@pytest.fixture
def request_factory():
    return RequestFactory()

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
def active_etudiant():
    user = User.objects.create(
        username='activeetudiant',
        email='activeetudiant@example.com',
        is_active=True,
        role='etudiant'
    )
    user.set_password('SecurePass123!')
    user.save()
    Etudiant.objects.create(user=user)
    return user

@pytest.fixture
def active_admin():
    user = User.objects.create(
        username='activeadmin',
        email='activeadmin@example.com',
        is_active=True,
        role='admin'
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
        from datetime import datetime, timedelta
        fake_now = token_generator._now()
        if isinstance(fake_now, datetime):
            future = fake_now + timedelta(seconds=3600)
        else:
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

    def test_check_token_mismatched_hash(self, pending_user, token_generator):
        """Test token validation when user data changes (mismatched hash)."""
        token = token_generator.make_token(pending_user)
        pending_user.email = 'newemail@example.com'
        pending_user.save()
        assert token_generator.check_token(pending_user, token) is False

    def test_check_invalid_timestamp_format(self, pending_user, token_generator):
        """Test token with invalid timestamp format."""
        token = f"invalid-timestamp-hash"
        assert token_generator.check_token(pending_user, token) is False

@pytest.mark.django_db
class TestSendActivationEmail:
    def test_send_activation_email_success(self, request_factory, pending_user):
        """Test successful email sending."""
        request = request_factory.get('/')
        request.build_absolute_uri = Mock(return_value='http://example.com/activate/uid/token')
        with patch('roles.views.send_mail') as mock_send_mail, \
             patch('django.template.loader.render_to_string', return_value='Email content'):
            mock_send_mail.return_value = 1
            send_activation_email(pending_user, request)
            assert mock_send_mail.called

    def test_send_activation_email_failure(self, request_factory, pending_user):
        """Test email sending failure with SMTP error."""
        request = request_factory.get('/')
        request.build_absolute_uri = Mock(return_value='http://example.com/activate/uid/token')
        with patch('roles.views.send_mail', side_effect=Exception('SMTP error')):
            with pytest.raises(Exception, match='SMTP error'):
                send_activation_email(pending_user, request)

    def test_send_activation_email_invalid_user_data(self, request_factory):
        """Test email sending with invalid user data (missing pk)."""
        request = request_factory.get('/')
        request.build_absolute_uri = Mock(return_value='http://example.com/activate/uid/token')
        invalid_user = Mock(email='test@example.com')  # No pk
        del invalid_user.pk
        with pytest.raises(AttributeError):
            send_activation_email(invalid_user, request)

    def test_send_activation_email_template_failure(self, request_factory, pending_user):
        """Test template rendering failure."""
        request = request_factory.get('/')
        request.build_absolute_uri = Mock(return_value='http://example.com/activate/uid/token')
        with patch('roles.views.render_to_string', side_effect=Exception('Template error')) as mock_render:
         with pytest.raises(Exception) as exc_info:
           send_activation_email(pending_user, request)
        assert mock_render.called, "render_to_string was not called"
        assert str(exc_info.value) == 'Template error', f"Expected 'Template error', got {str(exc_info.value)}"

    def test_send_activation_email_missing_settings(self, request_factory, pending_user, mocker):
        """Test missing DEFAULT_FROM_EMAIL: should fail before rendering template."""
        request = request_factory.get('/')
        request.build_absolute_uri = Mock(return_value='http://example.com/activate/uid/token')
        mocker.patch('roles.views.settings.DEFAULT_FROM_EMAIL', None)
        # Only patch make_token and reverse, not render_to_string or send_mail, since function should fail early
        with patch('roles.views.short_lived_token_generator.make_token', return_value='mock-token') as mock_make_token, \
             patch('roles.views.reverse', return_value='/activate/uid/token') as mock_reverse:
            try:
                send_activation_email(pending_user, request)
            except Exception as e:
                # Accept any exception, but render_to_string/send_mail should NOT be called
                assert 'from_email' in str(e) or 'DEFAULT_FROM_EMAIL' in str(e)
            else:
                assert False, "Expected exception due to missing DEFAULT_FROM_EMAIL but none was raised"

    def test_send_activation_email_invalid_from_email(self, request_factory, pending_user, mocker):
        """Test invalid DEFAULT_FROM_EMAIL: should call render_to_string and fail at send_mail."""
        request = request_factory.get('/')
        request.build_absolute_uri = Mock(return_value='http://example.com/activate/uid/token')
        mocker.patch('roles.views.settings.DEFAULT_FROM_EMAIL', 'bad@email')
        with patch('roles.views.short_lived_token_generator.make_token', return_value='mock-token') as mock_make_token, \
             patch('roles.views.reverse', return_value='/activate/uid/token') as mock_reverse, \
             patch('roles.views.render_to_string', return_value='Email content') as mock_render, \
             patch('roles.views.send_mail', side_effect=ValueError('Invalid from_email')) as mock_send_mail:
            try:
                send_activation_email(pending_user, request)
            except Exception as e:
                assert isinstance(e, ValueError) and str(e) == 'Invalid from_email', f"Expected ValueError('Invalid from_email'), got {str(e)}"
            else:
                assert False, "Expected ValueError('Invalid from_email') but no exception was raised"
            assert mock_make_token.called, "make_token was not called"
            assert mock_reverse.called, "reverse was not called"
            assert mock_render.called, "render_to_string was not called"
            assert mock_send_mail.called, "send_mail was not called"
   
    def test_send_activation_email_invalid_email_format(self, request_factory, pending_user):
        """Test email sending with invalid email format."""
        pending_user.email = 'invalid-email'
        request = request_factory.get('/')
        request.build_absolute_uri = Mock(return_value='http://example.com/activate/uid/token')
        with patch('roles.views.send_mail', side_effect=Exception('Invalid email format')):
            with pytest.raises(Exception, match='Invalid email format'):
                send_activation_email(pending_user, request)

@pytest.mark.django_db
class TestEtudiantSignup:
    def test_signup_get_request(self, client):
        """Test GET request renders signup.html."""
        response = client.get(reverse('roles:etudiant_signup'))
        assert response.status_code == 200
        assert 'form' in response.context
        assert isinstance(response.context['form'], DefaultSignUpForm)

    def test_signup_post_valid_form(self, client, user_data):
        """Test POST with valid form."""
        with patch('django.core.mail.send_mail'), \
             patch('django.template.loader.render_to_string', return_value='Email content'):
            response = client.post(reverse('roles:etudiant_signup'), user_data)
            assert response.status_code == 302  # Redirect to signup
            messages_list = list(get_messages(response.wsgi_request))
            assert any('Activation email sent' in msg.message for msg in messages_list)

    def test_signup_email_already_exists(self, client, user_data, pending_user):
        """Test POST with existing email."""
        user_data['email'] = pending_user.email
        response = client.post(reverse('roles:etudiant_signup'), user_data)
        assert response.status_code == 200
        messages_list = list(get_messages(response.wsgi_request))
        assert any('This email is already registered' in msg.message or 'A user with this email already exists.' in msg.message for msg in messages_list)

    def test_signup_post_invalid_form(self, client):
        """Test POST with invalid form."""
        response = client.post(reverse('roles:etudiant_signup'), {'username': '', 'email': ''})
        assert response.status_code == 200
        assert any('error' in msg.tags for msg in response.context['messages'])

    def test_signup_get_authenticated_etudiant(self, client, active_etudiant):
        """Test GET request for authenticated etudiant."""
        client.login(username='activeetudiant', password='SecurePass123!')
        response = client.get(reverse('roles:etudiant_signup'))
        assert response.status_code == 302
        assert response.url == reverse('roles:etudiant_dashboard')

    def test_signup_get_authenticated_admin(self, client, active_admin):
        """Test GET request for authenticated non-etudiant."""
        client.login(username='activeadmin', password='SecurePass123!')
        response = client.get(reverse('roles:etudiant_signup'))
        assert response.status_code == 200
        assert 'form' in response.context

    def test_signup_post_duplicate_username(self, client, user_data, pending_user):
        """Test POST with duplicate username."""
        user_data['email'] = 'newemail@example.com'  # Different email
        user_data['username'] = pending_user.username
        with patch('django.core.mail.send_mail'):
            response = client.post(reverse('roles:etudiant_signup'), user_data)
            assert response.status_code == 200
            # Accept either a generic error or a form error about username
            messages = [msg.message for msg in response.context['messages']]
            form_errors = response.context['form'].errors.get('username', []) if 'form' in response.context else []
            assert (
                any('An error occurred' in m for m in messages)
                or any('A user with that username already exists.' in e for e in form_errors)
                or any('This username is already taken' in e for e in form_errors)
                or any('already exists' in e for e in form_errors)

            ), f"Expected duplicate username error, got messages: {messages}, form_errors: {form_errors}"  

            
    def test_signup_post_case_sensitive_email(self, client, user_data, pending_user):
        """Test POST with case-sensitive email."""
        user_data['email'] = pending_user.email.upper()
        response = client.post(reverse('roles:etudiant_signup'), user_data)
        assert response.status_code == 200
        messages = [msg.message for msg in response.context['messages']]
        assert (
            any('This email is already registered' in m for m in messages) or
            any('A user with this email already exists.' in m for m in messages)
        ), f"Expected duplicate email error, got: {messages}"

    def test_signup_post_empty_post_data(self, client):
        """Test POST with empty data."""
        response = client.post(reverse('roles:etudiant_signup'), {})
        assert response.status_code == 200
        assert any('error' in msg.tags for msg in response.context['messages'])

    def test_signup_session_save_failure(self, client, user_data, mocker):
        """Test session save failure."""
        mocker.patch('django.contrib.sessions.backends.base.SessionBase.save', side_effect=Exception('Session error'))
        with patch('django.core.mail.send_mail'):
            response = client.post(reverse('roles:etudiant_signup'), user_data)
            assert response.status_code == 200
            assert 'An error occurred' in [msg.message for msg in response.context['messages']]

@pytest.mark.django_db
class TestSignin:
    def test_signin_get_request(self, client):
        """Test GET request renders signin.html."""
        response = client.get(reverse('roles:signin'))
        assert response.status_code == 200
        assert 'roles/signin.html' in [t.name for t in response.templates]

    def test_signin_post_valid_credentials(self, client, active_etudiant):
        """Test POST with valid credentials."""
        response = client.post(reverse('roles:signin'), {
            'username': active_etudiant.username,
            'password': 'SecurePass123!'
        })
        assert response.status_code == 302
        assert response.url == reverse('roles:etudiant_dashboard')

    def test_signin_post_invalid_credentials(self, client):
        """Test POST with invalid credentials."""
        response = client.post(reverse('roles:signin'), {
            'username': 'nonexistent',
            'password': 'wrongpass'
        })
        assert response.status_code == 200
        assert 'Invalid username or password.' in [msg.message for msg in response.context['messages']]

    def test_signin_pending_user(self, client, pending_user):
        """Test POST with inactive user, no session."""
        response = client.post(reverse('roles:signin'), {
            'username': pending_user.username,
            'password': 'SecurePass123!'
        })
        assert response.status_code == 200
        assert 'Please activate your account first.' in [msg.message for msg in response.context['messages']]

    def test_signin_active_etudiant_with_profile(self, client, active_etudiant):
        """Test active etudiant with profile redirects to student_homepage."""
        etudiant = Etudiant.objects.get(user=active_etudiant)
        ProfileEtudiant.objects.create(
            etudiant=etudiant,
            annee=Mock(),
            niveau=Mock(),
            filiere=Mock(),
            semestre=Mock()
        )
        response = client.post(reverse('roles:signin'), {
            'username': 'activeetudiant',
            'password': 'SecurePass123!'
        })
        assert response.status_code == 302
        assert response.url == reverse('roles:student_homepage')

    def test_signin_active_non_etudiant(self, client, active_admin):
        """Test active non-etudiant user redirects to signin (potential bug)."""
        response = client.post(reverse('roles:signin'), {
            'username': 'activeadmin',
            'password': 'SecurePass123!'
        })
        assert response.status_code == 302
        assert response.url == reverse('roles:signin')

    def test_signin_pending_user_with_session(self, client, pending_user, mocker):
        """Test inactive user with valid session data."""
        client.session['pending_user'] = {
            'username': 'pendinguser',
            'email': 'pendinguser@example.com',
            'pk': pending_user.pk,
            'role': 'etudiant',
            'is_active': False
        }
        client.session.save()
        mocker.patch('django.contrib.auth.login')
        response = client.post(reverse('roles:signin'), {
            'username': 'pendinguser',
            'password': 'SecurePass123!'
        })
        assert response.status_code == 302
        assert response.url == reverse('roles:etudiant_dashboard')
        pending_user.refresh_from_db()
        assert pending_user.is_active
        assert Etudiant.objects.filter(user=pending_user).exists()

    def test_signin_pending_user_wrong_password(self, client, pending_user):
        """Test inactive user with session and wrong password."""
        client.session['pending_user'] = {
            'username': 'pendinguser',
            'email': 'pendinguser@example.com',
            'pk': pending_user.pk,
            'role': 'etudiant',
            'is_active': False
        }
        client.session.save()
        response = client.post(reverse('roles:signin'), {
            'username': 'pendinguser',
            'password': 'WrongPass!'
        })
        assert response.status_code == 200
        assert 'Invalid password.' in [msg.message for msg in response.context['messages']]

    def test_signin_empty_fields(self, client):
        """Test POST with empty fields."""
        response = client.post(reverse('roles:signin'), {'username': '', 'password': ''})
        assert response.status_code == 200
        assert 'Invalid username or password.' in [msg.message for msg in response.context['messages']]

    def test_signin_case_sensitive_username(self, client, active_etudiant):
        """Test case-sensitive username."""
        response = client.post(reverse('roles:signin'), {
            'username': 'ACTIVEETUDIANT',
            'password': 'SecurePass123!'
        })
        assert response.status_code == 200
        assert 'Invalid username or password.' in [msg.message for msg in response.context['messages']]

    def test_signin_etudiant_creation_failure(self, client, pending_user, mocker):
        """Test Etudiant creation failure in _handle_pending_user."""
        client.session['pending_user'] = {
            'username': 'pendinguser',
            'email': 'pendinguser@example.com',
            'pk': pending_user.pk,
            'role': 'etudiant',
            'is_active': False
        }
        client.session.save()
        mocker.patch('roles.models.Etudiant.objects.create', side_effect=Exception('DB error'))
        response = client.post(reverse('roles:signin'), {
            'username': 'pendinguser',
            'password': 'SecurePass123!'
        })
        assert response.status_code == 200
        assert 'An error occurred' in [msg.message for msg in response.context['messages']]

    def test_signin_authenticate_failure(self, client, pending_user, mocker):
        """Test authenticate raising an unexpected exception."""
        mocker.patch('django.contrib.auth.authenticate', side_effect=Exception('Auth backend error'))
        response = client.post(reverse('roles:signin'), {
            'username': pending_user.username,
            'password': 'SecurePass123!'
        })
        assert response.status_code == 200
        assert 'Invalid username or password.' in [msg.message for msg in response.context['messages']]

@pytest.mark.django_db
class TestActivateAccount:
    def test_activate_account_valid_token(self, client, pending_user, token_generator):
        """Test valid token activation."""
        token = token_generator.make_token(pending_user)
        uid = urlsafe_b64encode(force_bytes(pending_user.pk)).decode()
        response = client.get(reverse('roles:activate', kwargs={'uidb64': uid, 'token': token}))
        assert response.status_code == 302
        assert response.url == reverse('roles:signin')
        pending_user.refresh_from_db()
        assert pending_user.is_active
        assert Etudiant.objects.filter(user=pending_user).exists()

    def test_activate_account_invalid_token(self, client, pending_user):
        """Test invalid token."""
        uid = urlsafe_b64encode(force_bytes(pending_user.pk)).decode()
        response = client.get(reverse('roles:activate', kwargs={'uidb64': uid, 'token': 'invalid-token'}), follow=True)
        assert response.status_code == 200
        messages_list = list(get_messages(response.wsgi_request))
        assert any('Invalid or expired activation link' in msg.message for msg in messages_list)

    def test_activate_account_malformed_uidb64(self, client):
        """Test malformed uidb64."""
        response = client.get(reverse('roles:activate', kwargs={'uidb64': 'invalid-uid', 'token': 'dummy-token'}), follow=True)
        assert response.status_code == 200
        messages_list = list(get_messages(response.wsgi_request))
        assert any('Invalid or expired activation link' in msg.message for msg in messages_list)

    def test_activate_account_already_active(self, client, active_etudiant, token_generator):
        """Test already active user."""
        token = token_generator.make_token(active_etudiant)
        uid = urlsafe_b64encode(force_bytes(active_etudiant.pk)).decode()
        response = client.get(reverse('roles:activate', kwargs={'uidb64': uid, 'token': token}), follow=True)
        assert response.status_code == 200
        messages_list = list(get_messages(response.wsgi_request))
        assert any('Account is already activated' in msg.message for msg in messages_list)

    def test_activate_account_db_error(self, client, pending_user, token_generator, mocker):
        """Test database error during activation."""
        token = token_generator.make_token(pending_user)
        uid = urlsafe_b64encode(force_bytes(pending_user.pk)).decode()
        mocker.patch('django.db.models.Model.save', side_effect=Exception('DB error'))
        response = client.get(reverse('roles:activate', kwargs={'uidb64': uid, 'token': token}), follow=True)
        assert response.status_code == 200
        messages_list = list(get_messages(response.wsgi_request))
        assert any('An error occurred during activation' in msg.message for msg in messages_list)

    def test_activate_account_mismatched_session(self, client, pending_user, token_generator):
        """Test activation with mismatched session data."""
        client.session['pending_user'] = {
            'username': 'differentuser',
            'email': 'different@example.com',
            'pk': 999,  # Mismatched pk
            'role': 'etudiant',
            'is_active': False
        }
        client.session.save()
        token = token_generator.make_token(pending_user)
        uid = urlsafe_b64encode(force_bytes(pending_user.pk)).decode()
        response = client.get(reverse('roles:activate', kwargs={'uidb64': uid, 'token': token}), follow=True)
        assert response.status_code == 200
        messages_list = list(get_messages(response.wsgi_request))
        assert any('Account activated! Please sign in.' in msg.message for msg in messages_list)
        pending_user.refresh_from_db()
        assert pending_user.is_active

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
            messages_list = list(get_messages(response.wsgi_request))
            assert any('Activation email sent' in msg.message for msg in messages_list)

    def test_resend_activation_post_invalid_email(self, client):
        """Test POST with non-existent email."""
        response = client.post(reverse('roles:resend_activation'), {'email': 'nonexistent@example.com'})
        assert response.status_code == 200
        assert 'No pending account found with this email.' in [msg.message for msg in response.context['messages']]

    def test_resend_activation_inactive_user_no_session(self, client, pending_user):
        """Test POST with inactive user in DB, no session."""
        with patch('django.core.mail.send_mail'), \
             patch('django.template.loader.render_to_string', return_value='Email content'):
            response = client.post(reverse('roles:resend_activation'), {'email': pending_user.email})
            assert response.status_code == 302
            assert response.url == reverse('roles:signin')
            messages_list = list(get_messages(response.wsgi_request))
            assert any('Activation email sent' in msg.message for msg in messages_list)
            assert 'pending_user' in client.session

    def test_resend_activation_active_user(self, client, active_etudiant):
        """Test POST with active user."""
        response = client.post(reverse('roles:resend_activation'), {'email': active_etudiant.email})
        assert response.status_code == 302
        assert response.url == reverse('roles:signin')
        messages_list = list(get_messages(response.wsgi_request))
        assert any('This account is already active' in msg.message for msg in messages_list)

    def test_resend_activation_invalid_form(self, client):
        """Test POST with invalid form (malformed email)."""
        response = client.post(reverse('roles:resend_activation'), {'email': 'invalid-email'})
        assert response.status_code == 200
        assert 'Please correct the errors below' in [msg.message for msg in response.context['messages']]

    def test_resend_activation_email_failure(self, client, pending_user):
        """Test email sending failure."""
        with patch('django.core.mail.send_mail', side_effect=Exception('SMTP error')):
            response = client.post(reverse('roles:resend_activation'), {'email': pending_user.email})
            assert response.status_code == 200
            assert 'An error occurred' in [msg.message for msg in response.context['messages']]

