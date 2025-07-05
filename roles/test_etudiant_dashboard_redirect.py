import pytest
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.test import Client
from roles.models import Etudiant, ProfileEtudiant, Annee, Filiere, Semestre, Niveau

User = get_user_model()

@pytest.mark.django_db
def test_etudiant_dashboard_redirects_if_profile_exists_get_and_post():
    """
    If a logged-in student with a profile tries to access etudiant_dashboard (GET or POST), they are redirected to student_homepage.
    """
    user = User.objects.create_user(username='student3', password='pass', role='etudiant', is_active=True)
    etudiant = Etudiant.objects.create(user=user)
    annee, _ = Annee.objects.get_or_create(annee="2025-2026")
    filiere = Filiere.objects.create(nom_filiere="Informatique-test-dashboard2")
    semestre = Semestre.objects.create(nom_semestre="S2-test-dashboard2")
    niveau = Niveau.objects.create(nom_niveau="L2-test-dashboard2")
    ProfileEtudiant.objects.create(etudiant=etudiant, annee=annee, niveau=niveau, filiere=filiere, semestre=semestre)
    client = Client()
    client.login(username='student3', password='pass')
    # GET request
    resp = client.get(reverse('roles:etudiant_dashboard'))
    assert resp.status_code == 302
    assert resp.url == reverse('roles:student_homepage')
    # POST request
    resp = client.post(reverse('roles:etudiant_dashboard'), {})
    assert resp.status_code == 302
    assert resp.url == reverse('roles:student_homepage')
