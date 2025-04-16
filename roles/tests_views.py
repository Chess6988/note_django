import pytest
from django.test import RequestFactory, Client
from django.urls import reverse
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from roles.views import signup_view, invited_signup_view, invite_user_view, activate_account, CustomLoginView
from roles.models import User, Invitation, Etudiant, Enseignant, Admin
from roles.forms import DefaultSignUpForm, InvitedSignUpForm, InviteUserForm
from unittest.mock import patch
from django.utils import timezone
from datetime import timedelta

@pytest.fixture
def client():
    return Client()

@pytest.fixture
def rf():
    return RequestFactory()

@pytest.fixture
def user():
    return User.objects.create_user(
        username="student",
        email="student@example.com",
        password="testpass123",
        role="etudiant"
    )

@pytest.fixture
def admin_user():
    return User.objects.create_user(
        username="admin",
        email="admin@example.com",
        password="testpass123",
        role="admin"
    )

@pytest.fixture
def superadmin_user():
    return User.objects.create_user(
        username="superadmin",
        email="superadmin@example.com",
        password="testpass123",
        role="superadmin"
    )

@pytest.mark.django_db
def test_signup_view_get(client):
    response = client.get(reverse('roles:signup'))
    assert response.status_code == 200
    assert 'form' in response.context
    assert isinstance(response.context['form'], DefaultSignUpForm)
    assert 'show_modal' not in response.context

@pytest.mark.django_db
@patch('roles.views.send_mail')
def test_signup_view_post_valid(mock_send_mail, client):
    data = {
        'username': 'newstudent',
        'email': 'newstudent@example.com',
        'password1': 'testpass123',
        'password2': 'testpass123',
        'first_name': 'John',
        'last_name': 'Doe',
        'phone_number': '1234567890'  # Added to satisfy form fields
    }
    response = client.post(reverse('roles:signup'), data)
    assert response.status_code == 200
    assert 'show_modal' in response.context
    assert response.context['show_modal'] is True
    user = User.objects.get(email='newstudent@example.com')
    assert user.role == 'etudiant'
    assert user.is_active is False
    assert Etudiant.objects.filter(user=user).exists()
    assert mock_send_mail.called

@pytest.mark.django_db
def test_invited_signup_view_get_valid_token(client, superadmin_user):
    invitation = Invitation.objects.create(
        invitee_email='invited@example.com',
        role='enseignant',
        pin='test-pin',
        inviter=superadmin_user,
        expires_at=timezone.now() + timedelta(minutes=10),
        status='pending'
    )
    response = client.get(reverse('roles:invited_signup', kwargs={'token': 'test-pin'}))
    assert response.status_code == 200
    assert 'form' in response.context
    assert isinstance(response.context['form'], InvitedSignUpForm)
    assert 'invitation' in response.context
    assert response.context['invitation'] == invitation

@pytest.mark.django_db
def test_invited_signup_view_get_invalid_token(client):
    response = client.get(reverse('roles:invited_signup', kwargs={'token': 'invalid-pin'}))
    assert response.status_code == 302
    assert response.url == reverse('roles:signup')

@pytest.mark.django_db
@patch('roles.views.send_mail')
def test_invited_signup_view_post_valid(mock_send_mail, client, superadmin_user):
    invitation = Invitation.objects.create(
        invitee_email='invited@example.com',
        role='enseignant',
        pin='test-pin',
        inviter=superadmin_user,
        expires_at=timezone.now() + timedelta(minutes=10),
        status='pending'
    )
    data = {
        'username': 'inviteduser',
        'password1': 'testpass123',
        'password2': 'testpass123',
        'first_name': 'Jane',
        'last_name': 'Doe',
        'phone_number': '1234567890'  # Added to satisfy form fields
    }
    response = client.post(reverse('roles:invited_signup', kwargs={'token': 'test-pin'}), data)
    assert response.status_code == 302  # Redirect on success
    assert User.objects.filter(email='invited@example.com').exists()
    assert mock_send_mail.called

@pytest.mark.django_db
def test_invite_user_view_get_admin(client, admin_user):
    client.login(username='admin', password='testpass123')
    response = client.get(reverse('roles:invite'))
    assert response.status_code == 200
    assert 'form' in response.context
    assert isinstance(response.context['form'], InviteUserForm)

@pytest.mark.django_db
def test_invite_user_view_get_non_admin(client, user):
    client.login(username='student', password='testpass123')
    response = client.get(reverse('roles:invite'))
    assert response.status_code == 302
    assert response.url == f"{reverse('roles:login')}?next=/invite/"

@pytest.mark.django_db
@patch('roles.views.send_mail')
def test_invite_user_view_post_valid_superadmin(mock_send_mail, client, superadmin_user):
    client.login(username='superadmin', password='testpass123')
    data = {
        'email': 'newuser@example.com',
        'role': 'admin'
    }
    response = client.post(reverse('roles:invite'), data)
    assert response.status_code == 302
    assert response.url == reverse('roles:invite')
    assert Invitation.objects.filter(invitee_email='newuser@example.com', role='admin').exists()
    assert mock_send_mail.called

@pytest.mark.django_db
def test_activate_account_valid(client, user):
    user.is_active = False
    user.save()
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    response = client.get(reverse('roles:activate', kwargs={'uidb64': uid, 'token': token}))
    assert response.status_code == 302
    assert response.url == reverse('roles:login')
    user.refresh_from_db()
    assert user.is_active is True

@pytest.mark.django_db
def test_activate_account_invalid(client, user):
    user.is_active = False
    user.save()
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    response = client.get(reverse('roles:activate', kwargs={'uidb64': uid, 'token': 'invalid-token'}))
    assert response.status_code == 302
    assert response.url == reverse('roles:signup')
    user.refresh_from_db()
    assert user.is_active is False

@pytest.mark.django_db
@patch.object(User, 'get_redirect_url')
def test_custom_login_view_success(mock_get_redirect_url, client, user):
    mock_get_redirect_url.return_value = '/etudiant/dashboard/'
    user.is_active = True
    user.save()
    data = {'username': 'student', 'password': 'testpass123'}
    response = client.post(reverse('roles:login'), data)
    assert response.status_code == 302
    assert response.url == '/etudiant/dashboard/'