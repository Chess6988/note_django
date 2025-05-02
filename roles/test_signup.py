from django.contrib.auth import get_user_model
from django.urls import reverse
import pytest

# Get the custom User model
User = get_user_model()

@pytest.mark.django_db
def test_etudiant_signup_post_success(client, mailoutbox):
    """Test POST request with successful signup."""
    post_data = {
        'username': 'testsignupuser',
        'email': 'signup_unique@example.com',
        'first_name': 'Test',
        'last_name': 'User',
        'password1': 'securePass123',
        'password2': 'securePass123',
    }
    response = client.post(reverse('roles:etudiant_signup'), data=post_data)
    assert response.status_code == 302  # Redirect to signin
    assert response.url == reverse('roles:signin')
    assert User.objects.filter(username='testsignupuser').exists()
    assert len(mailoutbox) == 1
    assert mailoutbox[0].subject == 'Activate Your Account'

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