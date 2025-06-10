from django.db import IntegrityError
import pytest
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.contrib.messages import get_messages
from django.core import mail
from django.test import RequestFactory
from roles.models import Etudiant
from roles.forms import DefaultSignUpForm
from django.contrib.sessions.middleware import SessionMiddleware
from django.contrib.messages.middleware import MessageMiddleware
from roles.views import (
    etudiant_signup,
    _handle_post_request_signup,
    _create_pending_user,
    _store_pending_user_in_session,
    signin,
    _handle_post_request_signin,
    _handle_pending_user,
    _handle_existing_user,
    _create_active_user,
    _finalize_user_setup
)
import logging

User = get_user_model()
@pytest.fixture
def request_with_session_and_messages(factory):
    def _request(method, url, data=None):
        request = getattr(factory, method)(url, data or {})
        # Add session middleware
        session_middleware = SessionMiddleware(lambda x: None)
        session_middleware.process_request(request)
        request.session.save()
        
        # Add messages middleware
        messages_middleware = MessageMiddleware(lambda x: None)
        messages_middleware.process_request(request)
        
        # Add auth middleware and user attribute
        from django.contrib.auth.middleware import AuthenticationMiddleware
        auth_middleware = AuthenticationMiddleware(lambda x: None)
        auth_middleware.process_request(request)
        
        # Add wsgi_request attribute
        setattr(request, 'wsgi_request', request)
        
        return request
    return _request

@pytest.fixture
def valid_signup_data():
    """Fixture for valid signup form data."""
    return {
        'username': 'testuser',
        'email': 'test@example.com',
        'password1': 'strongpass123',
        'password2': 'strongpass123',
        'first_name': 'Test',
        'last_name': 'User'
    }

@pytest.fixture
def invalid_signup_data():
    """Fixture for invalid signup form data."""
    return {
        'username': '',
        'email': 'invalid',
        'password1': 'weak',
        'password2': 'different',
        'first_name': '',
        'last_name': ''
    }

@pytest.fixture
def factory():
    """Fixture for RequestFactory."""
    return RequestFactory()

@pytest.mark.django_db
class TestEtudiantSignup:
    def test_signup_get(self, client):
        """Test GET request renders the signup form."""
        url = reverse('roles:etudiant_signup')
        response = client.get(url)
        
        assert response.status_code == 200
        assert 'form' in response.context
        assert isinstance(response.context['form'], DefaultSignUpForm)
        assert 'roles/signup.html' in [t.name for t in response.templates]

    def test_signup_post_valid(self, client, valid_signup_data, mocker):
        """Test POST request with valid data."""
        mocker.patch('roles.views.send_activation_email')
        url = reverse('roles:etudiant_signup')
        response = client.post(url, valid_signup_data)
        
        assert response.status_code == 302
        assert response.url == reverse('roles:signin')
        
        # Verify user creation
        user = User.objects.get(username=valid_signup_data['username'])
        assert user.is_active is False
        assert user.role == 'etudiant'
        assert user.email == valid_signup_data['email']
        
        # Verify session
        assert 'pending_user' in client.session
        assert client.session['pending_user']['username'] == valid_signup_data['username']
        
        # Verify messages
        messages = list(get_messages(response.wsgi_request))
        assert any('Activation email sent' in m.message for m in messages)

    def test_signup_post_invalid(self, client, invalid_signup_data):
        """Test POST request with invalid data."""
        url = reverse('roles:etudiant_signup')
        response = client.post(url, invalid_signup_data)
        
        assert response.status_code == 200
        assert 'form' in response.context
        assert response.context['form'].errors
        messages = list(get_messages(response.wsgi_request))
        assert any('Please correct the errors below' in m.message for m in messages)

    def test_signup_post_duplicate_username(self, client, valid_signup_data):
        """Test POST request with duplicate username."""
        User.objects.create_user(
            username=valid_signup_data['username'],
            email='other@example.com',
            password='otherpass123',
            role='etudiant'
        )
        url = reverse('roles:etudiant_signup')
        response = client.post(url, valid_signup_data)
        
        assert response.status_code == 200
        assert 'form' in response.context
        assert 'username' in response.context['form'].errors
        assert 'A user with that username already exists.' in response.context['form'].errors['username']
        messages = list(get_messages(response.wsgi_request))
        assert any('Username already exists' in m.message for m in messages)

    def test_signup_post_email_failure(self, client, valid_signup_data, mocker):
        """Test POST request with email sending failure."""
        mocker.patch('roles.views.send_activation_email', side_effect=Exception('Email error'))
        url = reverse('roles:etudiant_signup')
        response = client.post(url, valid_signup_data)
        
        assert response.status_code == 200
        assert 'form' in response.context
        messages = list(get_messages(response.wsgi_request))
        assert any('An error occurred' in m.message for m in messages)

    def test_signup_authenticated_etudiant(self, client):
        """Test authenticated etudiant is redirected."""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='pass123',
            role='etudiant',
            is_active=True
        )
        client.login(username='testuser', password='pass123')
        url = reverse('roles:etudiant_signup')
        response = client.get(url)
        
        assert response.status_code == 302
        assert response.url == user.get_redirect_url()

@pytest.mark.django_db
class TestSignin:
    def test_signin_get(self, client):
        """Test GET request renders the signin form."""
        url = reverse('roles:signin')
        response = client.get(url)
        
        assert response.status_code == 200
        assert 'roles/signin.html' in [t.name for t in response.templates]
        assert 'messages' in response.context

    def test_signin_post_valid_active_user(self, client):
        """Test POST request with valid credentials for active user."""
        user = User.objects.create_user(
            username='activeuser',
            email='active@example.com',
            password='pass123',
            is_active=True,
            role='etudiant'
        )
        Etudiant.objects.create(user=user)
        url = reverse('roles:signin')
        response = client.post(url, {'username': 'activeuser', 'password': 'pass123'})
        
        assert response.status_code == 302
        assert response.url == reverse('roles:etudiant_dashboard')
        assert '_auth_user_id' in client.session
        assert int(client.session['_auth_user_id']) == user.pk

    def test_signin_post_valid_inactive_pending_user(self, client, valid_signup_data):
        """Test POST request with valid credentials for inactive user with pending session."""
        user = User.objects.create_user(
            username=valid_signup_data['username'],
            email=valid_signup_data['email'],
            password=valid_signup_data['password1'],
            is_active=False,
            role='etudiant'
        )
        
        # Initialize session before setting session data
        client.get(reverse('roles:signin'))
        session = client.session
        session['pending_user'] = {
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'pk': user.pk,
            'is_active': False
        }
        session.save()
        
        response = client.post(reverse('roles:signin'), {
            'username': valid_signup_data['username'],
            'password': valid_signup_data['password1']
        })
        
        assert response.status_code == 302
        assert response.url == reverse('roles:etudiant_dashboard')
        user.refresh_from_db()
        assert user.is_active
        assert Etudiant.objects.filter(user=user).exists()
        assert 'pending_user' not in client.session
        assert '_auth_user_id' in client.session

    def test_signin_post_inactive_no_pending(self, client, valid_signup_data):
        """Test POST request with inactive user and no pending session."""
        user = User.objects.create_user(
            username=valid_signup_data['username'],
            email=valid_signup_data['email'],
            password=valid_signup_data['password1'],
            is_active=False,
            role='etudiant'
        )
        url = reverse('roles:signin')
        response = client.post(url, {
            'username': valid_signup_data['username'],
            'password': valid_signup_data['password1']
        })
        
        assert response.status_code == 200
        messages = list(get_messages(response.wsgi_request))
        assert any('Please activate your account first' in m.message for m in messages)

    def test_signin_post_invalid_credentials(self, client):
        """Test POST request with invalid credentials."""
        url = reverse('roles:signin')
        response = client.post(url, {'username': 'nonexistent', 'password': 'wrongpass'})
        
        assert response.status_code == 200
        messages = list(get_messages(response.wsgi_request))
        assert any('Invalid username or password' in m.message for m in messages)

    def test_signin_post_integrity_error(self, client, mocker, valid_signup_data):
        """Test POST request with IntegrityError during user retrieval."""
        mocker.patch('roles.models.User.objects.get', side_effect=IntegrityError)
        url = reverse('roles:signin')
        response = client.post(url, {
            'username': valid_signup_data['username'],
            'password': valid_signup_data['password1']
        })
        
        assert response.status_code == 200
        messages = list(get_messages(response.wsgi_request))
        assert any('Username or email already exists' in m.message for m in messages)

@pytest.mark.django_db
class TestHelperFunctions:
    def test_create_pending_user(self, factory, valid_signup_data):
        """Test _create_pending_user creates an inactive user."""
        request = factory.post(reverse('roles:etudiant_signup'), valid_signup_data)
        form = DefaultSignUpForm(data=valid_signup_data)
        assert form.is_valid()
        
        user = _create_pending_user(form)
        
        assert user.username == valid_signup_data['username']
        assert user.email == valid_signup_data['email']
        assert user.role == 'etudiant'
        assert user.is_active is False
        assert user.check_password(valid_signup_data['password1'])

    def test_store_pending_user_in_session(self, request_with_session_and_messages, valid_signup_data):
        """Test _store_pending_user_in_session stores user data."""
        user = User.objects.create_user(
            username=valid_signup_data['username'],
            email=valid_signup_data['email'],
            password=valid_signup_data['password1'],
            role='etudiant',
            is_active=False
        )
        request = request_with_session_and_messages('post', reverse('roles:etudiant_signup'))
        _store_pending_user_in_session(request, user)
        
        assert 'pending_user' in request.session
        assert request.session['pending_user']['username'] == user.username
        assert request.session['pending_user']['email'] == user.email
        assert request.session['pending_user']['role'] == 'etudiant'
        assert request.session['pending_user']['pk'] == user.pk
        assert request.session['pending_user']['is_active'] is False

    def test_handle_pending_user_valid(self, request_with_session_and_messages, valid_signup_data):
        """Test _handle_pending_user with valid credentials."""
        user = User.objects.create_user(
            username=valid_signup_data['username'],
            email=valid_signup_data['email'],
            password=valid_signup_data['password1'],
            is_active=False,
            role='etudiant'
        )
        request = request_with_session_and_messages('post', reverse('roles:signin'))
        request.user = user  # Set user explicitly for test
        
        response = _handle_pending_user(
            request,
            valid_signup_data['username'],
            valid_signup_data['password1'],
            {'username': user.username, 'email': user.email, 'role': user.role, 'pk': user.pk}
        )
        
        user.refresh_from_db()
        assert response.status_code == 302
        assert Etudiant.objects.filter(user=user).exists()

    def test_handle_pending_user_invalid_password(self, request_with_session_and_messages, valid_signup_data):
        """Test _handle_pending_user with invalid password."""
        user = User.objects.create_user(
            username=valid_signup_data['username'],
            email=valid_signup_data['email'],
            password=valid_signup_data['password1'],
            is_active=False,
            role='etudiant'
        )
        request = request_with_session_and_messages('post', reverse('roles:signin'), {
            'username': valid_signup_data['username'],
            'password': 'wrongpass'
        })
        request.session['pending_user'] = {
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'pk': user.pk,
            'is_active': False
        }
        request.session.save()

        response = _handle_pending_user(
            request,
            valid_signup_data['username'],
            'wrongpass',
            request.session['pending_user']
        )

        assert response.status_code == 200
        # Get messages from request instead of response
        messages = list(get_messages(request))
        assert any('Invalid password' in m.message for m in messages)
        user.refresh_from_db()
        assert not user.is_active

    def test_handle_existing_user_valid(self, request_with_session_and_messages):
        """Test _handle_existing_user with valid credentials."""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='pass123',
            is_active=True,
            role='etudiant'
        )
        request = request_with_session_and_messages('post', reverse('roles:signin'), {
            'username': 'testuser',
            'password': 'pass123'
        })
        response = _handle_existing_user(request, 'testuser', 'pass123')
        
        assert response.status_code == 302
        assert response.url == reverse('roles:etudiant_dashboard')
        assert request.user.is_authenticated

    def test_handle_existing_user_invalid(self, request_with_session_and_messages):
        """Test _handle_existing_user with invalid credentials."""
        User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='pass123',
            is_active=True,
            role='etudiant'
        )
        request = request_with_session_and_messages('post', reverse('roles:signin'), {
            'username': 'testuser',
            'password': 'wrongpass'
        })
        response = _handle_existing_user(request, 'testuser', 'wrongpass')

        assert response.status_code == 200
        # Get messages from request instead of response
        messages = list(get_messages(request))
        assert any('Invalid username or password' in m.message for m in messages)
        assert not hasattr(request, 'user') or not request.user.is_authenticated

    def test_create_active_user(self, request_with_session_and_messages):
        """Test _create_active_user activates a user."""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='pass123',
            is_active=False,
            role='etudiant'
        )
        pending_user = {
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'pk': user.pk,
            'is_active': False
        }
        activated_user = _create_active_user(pending_user)
        
        activated_user.refresh_from_db()
        assert activated_user.is_active
        assert activated_user.pk == user.pk

    def test_finalize_user_setup(self, request_with_session_and_messages):
        """Test _finalize_user_setup completes user setup."""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='pass123',
            is_active=True,
            role='etudiant'
        )
        request = request_with_session_and_messages('post', reverse('roles:signin'))
        request.session['pending_user'] = {
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'pk': user.pk,
            'is_active': True
        }
        request.session.save()
        
        _finalize_user_setup(request, user)
        
        assert Etudiant.objects.filter(user=user).exists()
        assert 'pending_user' not in request.session
        assert request.user.is_authenticated