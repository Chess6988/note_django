from django.contrib.auth import get_user_model
from django.urls import reverse
from django.core import mail
import pytest
from roles.models import Etudiant
from roles.forms import DefaultSignUpForm

User = get_user_model()

@pytest.mark.django_db
def test_etudiant_signup_get(client):
    """Test GET request for etudiant_signup view."""
    response = client.get(reverse('roles:etudiant_signup'))
    assert response.status_code == 200
    assert 'form' in response.context
    assert isinstance(response.context['form'], DefaultSignUpForm)

@pytest.mark.django_db
def test_etudiant_signup_post_valid(client):
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

    # Check that the user is created but inactive
    user = User.objects.get(username='testuser')
    assert user.is_active is False
    assert user.role == 'etudiant'

    # Check that an activation email was sent
    assert len(mail.outbox) == 1
    assert 'Activate Your Account' in mail.outbox[0].subject
    assert user.email in mail.outbox[0].to

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