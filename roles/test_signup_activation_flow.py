import pytest
from django.urls import reverse
from django.core import mail
from django.contrib.auth import get_user_model
from roles.models import User

@pytest.mark.django_db
def test_signup_stays_on_page_and_sends_email(client):
    """Test that after signup, user stays on signup page and activation email is sent."""
    signup_url = reverse('roles:etudiant_signup')
    data = {
        'username': 'testuser',
        'email': 'testuser@example.com',
        'password1': 'StrongPass123!',
        'password2': 'StrongPass123!',
        'first_name': 'Test',
        'last_name': 'User',
    }
    response = client.post(signup_url, data)
    assert response.status_code == 200
    assert b'Activation email sent' in response.content
    assert mail.outbox  # At least one email sent
    assert 'testuser@example.com' in mail.outbox[0].to
    # User should not be active yet
    user = User.objects.get(username='testuser')
    assert not user.is_active

@pytest.mark.django_db
def test_activation_redirects_to_signin(client):
    """Test that after clicking activation link, user is redirected to signin page."""
    from roles.views import short_lived_token_generator
    from django.utils.http import urlsafe_base64_encode
    from django.urls import reverse
    from django.utils.encoding import force_bytes

    user = User.objects.create_user(
        username='testuser2',
        email='testuser2@example.com',
        password='StrongPass123!',
        is_active=False,
        role='etudiant'
    )
    token = short_lived_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    activation_url = reverse('roles:activate', kwargs={'uidb64': uid, 'token': token})
    session = client.session
    session['pending_user'] = {
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'role': user.role,
        'password': user.password,
        'is_active': user.is_active,
        'pk': user.pk
    }
    session.save()
    response = client.get(activation_url, follow=True)
    assert response.redirect_chain[-1][0].endswith(reverse('roles:signin'))
    user.refresh_from_db()
    assert user.is_active
