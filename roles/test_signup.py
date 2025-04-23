# roles/tests/test_signup.py

import pytest
from django.urls import reverse
from roles.models import User, Invitation
from django.utils import timezone
from datetime import timedelta
import uuid

@pytest.mark.django_db
def test_signup_get(client):
    response = client.get(reverse('roles:signup'))
    assert response.status_code == 200
    assert b'Student Signup' in response.content

@pytest.mark.django_db
def test_invited_signup_get(client):
    inviter = User.objects.create_user(
        username='admin_user',
        email='admin@example.com',
        password='adminpass123',
        role='admin',
        is_active=True
    )
    invitation = Invitation.objects.create(
        invitee_email='invitee@example.com',
        role='admin',
        pin=str(uuid.uuid4()),
        inviter=inviter,
        expires_at=timezone.now() + timedelta(days=7),
        status='pending'
    )
    response = client.get(reverse('roles:invited_signup', args=[invitation.pin]))
    assert response.status_code == 200
    assert b'Invited Signup' in response.content

@pytest.mark.django_db
def test_signup_post_success(client, mailoutbox):
    post_data = {
        'username': 'testsignupuser',
        'email': 'signup_unique@example.com',
        'password1': 'securePass123',
        'password2': 'securePass123'
    }
    response = client.post(reverse('roles:signup'), data=post_data)
    assert response.status_code == 200
    html = response.content.decode()
    assert 'id="signupSuccessModal"' in html
    assert User.objects.filter(username='testsignupuser').exists()
    assert len(mailoutbox) == 1
