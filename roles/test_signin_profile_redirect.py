import pytest
from django.urls import reverse
from django.contrib.auth import get_user_model
from roles.models import Etudiant, ProfileEtudiant, Annee, Filiere, Semestre, Niveau

User = get_user_model()

@pytest.mark.django_db
def test_signin_redirects_to_dashboard_if_no_profile(client):
    """If student has no profile, redirect to etudiant_dashboard after signin."""
    user = User.objects.create_user(username='student1', password='pass123', role='etudiant', is_active=True)
    Etudiant.objects.create(user=user)
    url = reverse('roles:signin')
    response = client.post(url, {'username': 'student1', 'password': 'pass123'})
    assert response.status_code == 302
    assert response.url == reverse('roles:etudiant_dashboard')

@pytest.mark.django_db
def test_signin_redirects_to_homepage_if_profile_exists(client):
    """If student has a profile, redirect to student_homepage after signin."""
    user = User.objects.create_user(username='student2', password='pass123', role='etudiant', is_active=True)
    etudiant = Etudiant.objects.create(user=user)
    annee, _ = Annee.objects.get_or_create(annee="2024-2025")
    filiere, _ = Filiere.objects.get_or_create(nom_filiere="Informatique")
    semestre, _ = Semestre.objects.get_or_create(nom_semestre="S1")
    niveau, _ = Niveau.objects.get_or_create(nom_niveau="L1")
    ProfileEtudiant.objects.create(
        etudiant=etudiant,
        annee=annee,
        filiere=filiere,
        semestre=semestre,
        niveau=niveau
    )
    url = reverse('roles:signin')
    response = client.post(url, {'username': 'student2', 'password': 'pass123'})
    assert response.status_code == 302
    assert response.url == reverse('roles:student_homepage')
