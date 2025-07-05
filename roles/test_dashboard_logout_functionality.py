import pytest
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.test import Client
from roles.models import Etudiant, ProfileEtudiant, Annee, Filiere, Semestre, Niveau

User = get_user_model()

@pytest.mark.django_db
def test_etudiant_dashboard_redirects_if_profile_exists():
    """
    If a logged-in student with a profile tries to access etudiant_dashboard, they are redirected to student_homepage.
    """
    user = User.objects.create_user(username='student1', password='pass', role='etudiant', is_active=True)
    etudiant = Etudiant.objects.create(user=user)
    # Use a unique value for annee to avoid unique constraint errors
    annee, _ = Annee.objects.get_or_create(annee="2024-2025")  # <= 9 chars, get_or_create avoids duplicate error
    filiere = Filiere.objects.create(nom_filiere="Informatique-test-dashboard")
    semestre = Semestre.objects.create(nom_semestre="S1-test-dashboard")
    niveau = Niveau.objects.create(nom_niveau="L1-test-dashboard")
    ProfileEtudiant.objects.create(etudiant=etudiant, annee=annee, niveau=niveau, filiere=filiere, semestre=semestre)
    client = Client()
    client.login(username='student1', password='pass')
    resp = client.get(reverse('roles:etudiant_dashboard'))
    assert resp.status_code == 302
    assert resp.url == reverse('roles:student_homepage')

@pytest.mark.django_db
def test_logout_requires_post_and_csrf():
    """
    The logout view only accepts POST with CSRF token. GET should be 405, POST without CSRF should be 403.
    """
    user = User.objects.create_user(username='student2', password='pass', role='etudiant', is_active=True)
    etudiant = Etudiant.objects.create(user=user)
    client = Client(enforce_csrf_checks=True)
    client.login(username='student2', password='pass')
    # GET should be 405
    resp = client.get(reverse('roles:logout'))
    assert resp.status_code == 405
    # POST without CSRF should be 403
    resp = client.post(reverse('roles:logout'))
    assert resp.status_code == 403
    # POST with CSRF should succeed
    # Use a view that always sets the CSRF cookie (dashboard renders a form)
    resp = client.get(reverse('roles:etudiant_dashboard'))
    csrftoken = resp.cookies['csrftoken'].value
    resp = client.post(reverse('roles:logout'), HTTP_X_CSRFTOKEN=csrftoken)
    assert resp.status_code == 302
    assert resp.url == reverse('roles:signin')
