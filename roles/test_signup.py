from http import client
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.core import mail
import pytest
from roles.models import Etudiant
from roles.forms import DefaultSignUpForm
from django.contrib.messages import get_messages
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from roles.views import short_lived_token_generator

User = get_user_model()

@pytest.fixture
def valid_signup_data():
    return {
        'username': 'testuser',
        'email': 'test@example.com',
        'password1': 'strongpass123',
        'password2': 'strongpass123'
    }

@pytest.mark.django_db
def test_etudiant_signup_get(client):
    """Test GET request for etudiant_signup view."""
    response = client.get(reverse('roles:etudiant_signup'))
    assert response.status_code == 200
    assert 'form' in response.context
    assert isinstance(response.context['form'], DefaultSignUpForm)
    assert 'roles/signup.html' in [t.name for t in response.templates]

@pytest.mark.django_db
def test_etudiant_signup_post_valid(client, valid_signup_data):
    """Test POST request with valid data for etudiant_signup view."""
    data = {
        'username': 'testuser',
        'email': 'testuser@example.com',
        'password1': 'strongpassword123',
        'password2': 'strongpassword123',
        'first_name': 'Test',
        'last_name': 'User'
    }
    response = client.post(reverse('roles:etudiant_signup'), data=data)
    assert response.status_code == 302  # Redirect after success
    assert response.url == reverse('roles:signin')
    
    # Verify user creation
    user = User.objects.get(username=data['username'])
    assert user.is_active is False
    assert user.role == 'etudiant'
    assert user.email == data['email']
    
    # Verify session
    assert 'pending_user' in client.session
    
    # Verify email
    assert len(mail.outbox) == 1
    assert mail.outbox[0].subject == 'Activate Your Account'
    assert data['email'] in mail.outbox[0].to

@pytest.mark.django_db
def test_etudiant_signup_post_invalid(client):
    """Test POST request with invalid data for etudiant_signup view."""
    data = {
        'username': '',  # Invalid username
        'email': 'invalidemail',  # Invalid email
        'password1': 'short',  # Weak password
        'password2': 'short',
        'first_name': '',
        'last_name': ''
    }
    response = client.post(reverse('roles:etudiant_signup'), data=data)
    assert response.status_code == 200  # Form re-rendered with errors
    assert 'form' in response.context
    assert response.context['form'].errors
    messages = list(get_messages(response.wsgi_request))
    assert any('Please correct the errors below' in m.message for m in messages)

@pytest.mark.django_db
def test_etudiant_signup_authenticated_redirect(client, django_user_model):
    """Test that authenticated users are redirected."""
    user = django_user_model.objects.create_user(username='testuser', password='password', role='etudiant')
    client.login(username='testuser', password='password')

    response = client.get(reverse('roles:etudiant_signup'))
    assert response.status_code == 302
    assert response.url == user.get_redirect_url()

@pytest.mark.django_db
def test_etudiant_signup_email_failure(client, mocker):
    """Test email failure during signup."""
    data = {
        'username': 'testuser',
        'email': 'testuser@example.com',
        'password1': 'strongpassword123',
        'password2': 'strongpassword123',
        'first_name': 'Test',
        'last_name': 'User'
    }

    # Mock send_mail to raise an exception
    mocker.patch('roles.views.send_mail', side_effect=Exception('Email error'))

    response = client.post(reverse('roles:etudiant_signup'), data=data)
    assert response.status_code == 200  # Form re-rendered with error message
    assert 'An error occurred. Please try again later.' in response.content.decode()

@pytest.mark.django_db
def test_etudiant_signup_post_success(client, mailoutbox):
    """Test POST request with successful signup."""
    post_data = {
        'username': 'testuser',
        'email': 'test@example.com',
        'first_name': 'Test',
        'last_name': 'User',
        'password1': 'securePass123',
        'password2': 'securePass123',
    }
    response = client.post(reverse('roles:etudiant_signup'), data=post_data)
    assert response.status_code == 302  # Redirect after success
    assert response.url == reverse('roles:signin')

    # Check that the user is created but inactive
    user = User.objects.get(username='testuser')
    assert user.is_active is False
    assert user.role == 'etudiant'

    # Check that an activation email was sent
    assert len(mailoutbox) == 1
    assert 'Activate Your Account' in mailoutbox[0].subject
    assert user.email in mailoutbox[0].to

@pytest.mark.django_db
def test_etudiant_signup_duplicate_username(client):
    """Test POST request with duplicate username."""
    User.objects.create_user(username='testsignupuser', email='existing@example.com', password='testpass123', role='etudiant')
    post_data = {
        'username': 'testsignupuser',  # Duplicate username
        'email': 'new@example.com',
        'first_name': 'Test',
        'last_name': 'User',
        'password1': 'securePass123',
        'password2': 'securePass123',
    }
    response = client.post(reverse('roles:etudiant_signup'), data=post_data)
    assert response.status_code == 200
    form = response.context['form']
    assert 'username' in form.errors
    assert "A user with that username already exists." in form.errors['username']

@pytest.mark.django_db
def test_etudiant_signup_password_mismatch(client):
    """Test POST request with mismatched passwords."""
    post_data = {
        'username': 'testsignupuser',
        'email': 'signup_unique@example.com',
        'first_name': 'Test',
        'last_name': 'User',
        'password1': 'securePass123',
        'password2': 'differentPass456',
    }
    response = client.post(reverse('roles:etudiant_signup'), data=post_data)
    assert response.status_code == 200
    form = response.context['form']
    assert 'password2' in form.errors
    assert "The two password fields didn’t match." in form.errors['password2']

@pytest.mark.django_db
def test_etudiant_signup_authenticated_user(client):
    """Test signup access when user is already authenticated."""
    user = User.objects.create_user(username='testuser', password='testpass123', role='etudiant')
    client.login(username='testuser', password='testpass123')
    response = client.get(reverse('roles:etudiant_signup'))
    assert response.status_code == 302  # Should redirect since user is authenticated

@pytest.mark.django_db
class TestEtudiantSignup:
    def test_signup_get_view(self, client):
        """Test that GET request renders signup form correctly."""
        url = reverse('roles:etudiant_signup')
        response = client.get(url)
        
        assert response.status_code == 200
        assert 'form' in response.context
        assert isinstance(response.context['form'], DefaultSignUpForm)
        assert 'roles/signup.html' in [t.name for t in response.templates]

    def test_signup_post_valid(self, client, valid_signup_data):
        """Test successful signup process."""
        url = reverse('roles:etudiant_signup')
        response = client.post(url, valid_signup_data)
        
        assert response.status_code == 302
        assert response.url == reverse('roles:signin')
        
        # Verify user creation
        user = User.objects.get(username=valid_signup_data['username'])
        assert not user.is_active
        assert user.role == 'etudiant'
        assert user.email == valid_signup_data['email']
        
        # Verify session
        assert 'pending_user' in client.session
        
        # Verify email
        assert len(mail.outbox) == 1
        assert mail.outbox[0].subject == 'Activate Your Account'
        assert valid_signup_data['email'] in mail.outbox[0].to

    def test_signup_post_existing_username(self, client, valid_signup_data):
        """Test signup with existing username."""
        # Create user first
        User.objects.create_user(
            username=valid_signup_data['username'],
            email='other@example.com',
            password='otherpass123'
        )
        
        url = reverse('roles:etudiant_signup')
        response = client.post(url, valid_signup_data)
        
        assert response.status_code == 200
        messages = list(get_messages(response.wsgi_request))
        assert 'Username already exists' in [m.message for m in messages]

    def test_signup_post_invalid_data(self, client):
        """Test signup with invalid data."""
        url = reverse('roles:etudiant_signup')
        invalid_data = {
            'username': '',
            'email': 'invalid',
            'password1': 'weak',
            'password2': 'different'
        }
        response = client.post(url, invalid_data)
        
        assert response.status_code == 200
        assert 'form' in response.context
        assert response.context['form'].errors
        messages = list(get_messages(response.wsgi_request))
        assert any('Please correct the errors below' in m.message for m in messages)

    def test_signup_authenticated_user(self, client, valid_signup_data):
        """Test that authenticated etudiant is redirected."""
        # Create and login as etudiant
        user = User.objects.create_user(
            username='existing',
            email='existing@example.com',
            password='pass123',
            role='etudiant',
            is_active=True
        )
        Etudiant.objects.create(user=user)
        client.login(username='existing', password='pass123')
        
        url = reverse('roles:etudiant_signup')
        response = client.get(url)
        
        assert response.status_code == 302
        assert response.url == reverse('roles:etudiant_dashboard')

    def test_activation_valid_token(self, client, valid_signup_data):
        """Test successful account activation."""
        # Create inactive user
        user = User.objects.create_user(
            username=valid_signup_data['username'],
            email=valid_signup_data['email'],
            password=valid_signup_data['password1'],
            is_active=False,
            role='etudiant'
        )
        
        # Store in session
        session = client.session
        session['pending_user'] = {
            'username': user.username,
            'email': user.email,
            'password': user.password,
            'role': user.role,
            'is_active': user.is_active,
            'pk': user.pk
        }
        session.save()
        
        # Generate activation token
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        token = short_lived_token_generator.make_token(user)
        
        url = reverse('roles:activate', kwargs={'uidb64': uidb64, 'token': token})
        response = client.get(url)
        
        assert response.status_code == 302
        assert response.url == reverse('roles:signin')
        
        # Verify user is active
        user.refresh_from_db()
        assert user.is_active
        assert Etudiant.objects.filter(user=user).exists()
        assert 'pending_user' not in client.session

@pytest.mark.django_db
class TestSignin:
    def test_signin_get(self, client):
        """Test that GET request renders signin form."""
        url = reverse('roles:signin')
        response = client.get(url)
        assert response.status_code == 200
        assert 'roles/signin.html' in [t.name for t in response.templates]

    def test_signin_post_valid(self, client):
        """Test successful signin with active user."""
        user = User.objects.create_user(
            username='activeuser',
            email='active@example.com',
            password='pass123',
            is_active=True,
            role='etudiant'
        )
        Etudiant.objects.create(user=user)
        
        url = reverse('roles:signin')
        response = client.post(url, {
            'username': 'activeuser',
            'password': 'pass123'
        })
        
        assert response.status_code == 302
        assert response.url == reverse('roles:etudiant_dashboard')
        assert '_auth_user_id' in client.session
        assert int(client.session['_auth_user_id']) == user.pk

    def test_signin_post_inactive_user(self, client, valid_signup_data):
        """Test signin attempt with inactive user."""
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
        """Test signin with invalid credentials."""
        url = reverse('roles:signin')
        response = client.post(url, {
            'username': 'nonexistent',
            'password': 'wrongpass'
        })
        
        assert response.status_code == 200
        messages = list(get_messages(response.wsgi_request))
        assert any('Invalid username or password' in m.message for m in messages)

@pytest.mark.django_db
class TestResendActivation:
    def test_resend_get(self, client):
        """Test that GET request renders resend form."""
        url = reverse('roles:resend_activation')
        response = client.get(url)
        
        assert response.status_code == 200
        assert 'form' in response.context
        assert 'roles/resend_activation.html' in [t.name for t in response.templates]

    def test_resend_post_valid(self, client, valid_signup_data):
        """Test successful resend activation email."""
        user = User.objects.create_user(
            username=valid_signup_data['username'],
            email=valid_signup_data['email'],
            password=valid_signup_data['password1'],
            is_active=False,
            role='etudiant'
        )
        
        url = reverse('roles:resend_activation')
        response = client.post(url, {'email': valid_signup_data['email']})
        
        assert response.status_code == 302
        assert response.url == reverse('roles:signin')
        assert len(mail.outbox) == 1
        assert mail.outbox[0].subject == 'Activate Your Account'
        
        # Verify session
        assert 'pending_user' in client.session
        assert client.session['pending_user']['email'] == valid_signup_data['email']

    def test_resend_post_nonexistent_email(self, client):
        """Test resend activation with nonexistent email."""
        url = reverse('roles:resend_activation')
        response = client.post(url, {'email': 'nonexistent@example.com'})
        
        messages = list(get_messages(response.wsgi_request))
        assert any('No pending account found' in m.message for m in messages)
    
    def test_resend_post_active_user(self, client, valid_signup_data):
        """Test resend activation for already active user."""
        user = User.objects.create_user(
            username=valid_signup_data['username'],
            email=valid_signup_data['email'],
            password=valid_signup_data['password1'],
            is_active=True,
            role='etudiant'
        )
        
        # Store in session to simulate the real flow
        session = client.session
        session['pending_user'] = {
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'pk': user.pk,
            'is_active': True
        }
        session.save()
        
        url = reverse('roles:resend_activation')
        response = client.post(url, {'email': valid_signup_data['email']})
        
        assert response.status_code == 200
        messages = list(get_messages(response.wsgi_request))
        assert any('This account is already active' in m.message for m in messages)