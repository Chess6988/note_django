
import json
import pytest
from django.test import Client
from django.urls import reverse
from django.contrib.auth.models import AnonymousUser
from django.contrib import messages
from django.db import IntegrityError
from roles.models import (
    User, Etudiant, Annee, Niveau, Filiere, Semestre, Matiere, MatiereCommune,
    ProfileEtudiant, MatiereEtudiant, MatiereCommuneEtudiant
)
from roles.forms import StudentProfileForm
import logging

# Disable logging during tests to reduce noise
logging.disable(logging.CRITICAL)

@pytest.fixture
def client():
    """Provide a Django test client."""
    return Client()

@pytest.fixture
def student_user(db):
    """Create a student user with an Etudiant profile."""
    user = User.objects.create_user(
        username='student1',
        email='student1@example.com',
        password='testpass123',
        role='etudiant',
        first_name='John',
        last_name='Doe',
        is_active=True
    )
    etudiant = Etudiant.objects.create(user=user)
    return user

@pytest.fixture
def academic_data(db):
    """Create academic data for testing."""
    annee, _ = Annee.objects.get_or_create(annee='2023-2024')
    niveau = Niveau.objects.create(nom_niveau='L1')
    filiere = Filiere.objects.create(nom_filiere='Computer Science')
    semestre = Semestre.objects.create(nom_semestre='S1')
    matiere = Matiere.objects.create(
        nom_matiere='Mathematics',
        course_code='MATH101',
        filiere=filiere,
        semestre=semestre,
        niveau=niveau
    )
    matiere_commune = MatiereCommune.objects.create(
        nom_matiere_commune='English',
        course_code='ENG101',
        filiere=None,
        semestre=semestre,
        niveau=niveau
    )
    return {
        'annee': annee,
        'niveau': niveau,
        'filiere': filiere,
        'semestre': semestre,
        'matiere': matiere,
        'matiere_commune': matiere_commune
    }

@pytest.mark.django_db
class TestSubjectGeneration:
    """Tests for subject generation functionality."""

    def test_subject_data_structure(self, client, student_user, academic_data):
        """Test the structure of subject data in context."""
        client.login(username='student1', password='testpass123')
        response = client.get(reverse('roles:etudiant_dashboard'))
        assert response.status_code == 200
        matiere_data = json.loads(response.context['matiere_data'])
        matiere_commune_data = json.loads(response.context['matiere_commune_data'])
        key = f"{academic_data['filiere'].id}_{academic_data['semestre'].id}_{academic_data['niveau'].id}"
        none_key = f"None_{academic_data['semestre'].id}_{academic_data['niveau'].id}"
        assert key in matiere_data
        assert matiere_data[key][0]['id'] == academic_data['matiere'].id
        assert matiere_data[key][0]['nom'] == 'Mathematics'
        assert none_key in matiere_commune_data
        assert matiere_commune_data[none_key][0]['id'] == academic_data['matiere_commune'].id
        assert matiere_commune_data[none_key][0]['nom'] == 'English'

    def test_profile_creation_with_subjects(self, client, student_user, academic_data):
        """Test profile creation with subject selection."""
        client.login(username='student1', password='testpass123')
        form_data = {
            'annee': academic_data['annee'].id,
            'niveau': academic_data['niveau'].id,
            'filiere': academic_data['filiere'].id,
            'semestre': academic_data['semestre'].id,
            'matiere': academic_data['matiere'].id,
            'matiere_commune': academic_data['matiere_commune'].id
        }
        response = client.post(reverse('roles:etudiant_dashboard'), form_data)
        if response.status_code != 302:
            form = response.context.get('form')
            print("Form errors:", form.errors.as_text() if form else "No form in context")
            print("Context:", response.context)
        assert response.status_code == 302, f"Expected 302, got {response.status_code}"
        assert response.url == reverse('roles:etudiant_dashboard')
        assert ProfileEtudiant.objects.count() == 1
        assert MatiereEtudiant.objects.count() == 1
        assert MatiereCommuneEtudiant.objects.count() == 1
        messages_list = list(messages.get_messages(response.wsgi_request))
        assert any('Profile created successfully.' in str(msg) for msg in messages_list)

    def test_invalid_subject_combination(self, client, student_user, academic_data):
        """Test submission with invalid subject combination."""
        client.login(username='student1', password='testpass123')
        form_data = {
            'annee': academic_data['annee'].id,
            'niveau': academic_data['niveau'].id,
            'filiere': academic_data['filiere'].id,
            'semestre': academic_data['semestre'].id,
            'matiere': '',
            'matiere_commune': ''
        }
        Matiere.objects.all().delete()
        response = client.post(reverse('roles:etudiant_dashboard'), form_data)
        if response.status_code != 200:
            print("Unexpected redirect:", response.url)
            form = response.context.get('form')
            print("Form errors:", form.errors.as_text() if form else "No form in context")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        assert 'matiere_unavailable_message' in response.context
        assert 'No subjects are available' in response.context['matiere_unavailable_message']

    def test_subject_managers(self, academic_data):
        """Test Matiere and MatiereCommune manager methods."""
        matieres = Matiere.objects.by_combination(
            filiere=academic_data['filiere'],
            semestre=academic_data['semestre'],
            niveau=academic_data['niveau']
        )
        assert matieres.count() == 1
        assert matieres.first() == academic_data['matiere']
        matieres_commune = MatiereCommune.objects.by_combination(
            filiere=None,
            semestre=academic_data['semestre'],
            niveau=academic_data['niveau']
        )
        assert matieres_commune.count() == 1
        assert matieres_commune.first() == academic_data['matiere_commune']