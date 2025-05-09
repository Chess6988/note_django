import pytest
from django.urls import reverse
from django.db import IntegrityError
from django.core.serializers.json import DjangoJSONEncoder
import json
from .models import (
    Annee, Filiere, Niveau, Semestre, Etudiant, Matiere, MatiereCommune, ProfileEtudiant
)
from .forms import StudentProfileForm
from roles.models import User  # Updated import to use custom User model

# Fixtures
@pytest.fixture
def student_user():
    """Create a student user with an Etudiant profile."""
    user = User.objects.create_user(username='student', password='password')
    etudiant = Etudiant.objects.create(user=user, filiere="Informatique", niveau="L1")
    return user

@pytest.fixture
def annee():
    """Create an Annee instance."""
    return Annee.objects.create(annee="2023-2024")

@pytest.fixture
def filiere():
    """Create a Filiere instance."""
    return Filiere.objects.create(nom_filiere="Informatique")

@pytest.fixture
def niveau():
    """Create a Niveau instance."""
    return Niveau.objects.create(nom_niveau="L1")

@pytest.fixture
def semestre():
    """Create a Semestre instance."""
    return Semestre.objects.create(nom_semestre="S1")

@pytest.fixture
def matiere(filiere, semestre, niveau):
    """Create a Matiere instance."""
    return Matiere.objects.create(
        nom_matiere="Mathématiques", course_code="MATH101",
        filiere=filiere, semestre=semestre, niveau=niveau
    )

@pytest.fixture
def matiere_commune(filiere, semestre, niveau):
    """Create a MatiereCommune instance."""
    return MatiereCommune.objects.create(
        nom_matiere_commune="Anglais", course_code="ANG101",
        filiere=filiere, semestre=semestre, niveau=niveau
    )

# Model Tests (Unchanged)
@pytest.mark.django_db
class TestModels:
    def test_annee_creation(self, annee):
        """Test Annee model creation."""
        assert Annee.objects.count() == 1
        assert annee.annee == "2023-2024"

    def test_filiere_creation(self, filiere):
        """Test Filiere model creation."""
        assert Filiere.objects.count() == 1
        assert filiere.nom_filiere == "Informatique"

    def test_semestre_creation(self, semestre):
        """Test Semestre model creation."""
        assert Semestre.objects.count() == 1
        assert semestre.nom_semestre == "S1"

    def test_matiere_creation(self, matiere):
        """Test Matiere model creation and relationships."""
        assert Matiere.objects.count() == 1
        assert matiere.nom_matiere == "Mathématiques"
        assert matiere.course_code == "MATH101"
        assert matiere.filiere.nom_filiere == "Informatique"
        assert matiere.semestre.nom_semestre == "S1"
        assert matiere.niveau.nom_niveau == "L1"

    def test_matiere_unique_course_code(self, filiere, semestre, niveau):
        """Test Matiere unique course_code constraint."""
        Matiere.objects.create(nom_matiere="Physique", course_code="PHYS101", filiere=filiere, semestre=semestre, niveau=niveau)
        with pytest.raises(IntegrityError):
            Matiere.objects.create(nom_matiere="Chimie", course_code="PHYS101", filiere=filiere, semestre=semestre, niveau=niveau)

    def test_matiere_commune_creation(self, matiere_commune):
        """Test MatiereCommune model creation and relationships."""
        assert MatiereCommune.objects.count() == 1
        assert matiere_commune.nom_matiere_commune == "Anglais"
        assert matiere_commune.course_code == "ANG101"
        assert matiere_commune.filiere.nom_filiere == "Informatique"
        assert matiere_commune.semestre.nom_semestre == "S1"
        assert matiere_commune.niveau.nom_niveau == "L1"

    def test_matiere_commune_unique_course_code(self, filiere, semestre, niveau):
        """Test MatiereCommune unique course_code constraint."""
        MatiereCommune.objects.create(nom_matiere_commune="Français", course_code="FR101", filiere=filiere, semestre=semestre, niveau=niveau)
        with pytest.raises(IntegrityError):
            MatiereCommune.objects.create(nom_matiere_commune="Espagnol", course_code="FR101", filiere=filiere, semestre=semestre, niveau=niveau)

    def test_etudiant_creation(self, student_user):
        """Test Etudiant model creation and relationship with User."""
        assert Etudiant.objects.count() == 1
        assert student_user.etudiant_profile.filiere == "Informatique"
        assert student_user.etudiant_profile.niveau == "L1"

    def test_etudiant_one_to_one(self, student_user):
        """Test Etudiant OneToOneField constraint with User."""
        with pytest.raises(IntegrityError):
            Etudiant.objects.create(user=student_user, filiere="Mathématiques", niveau="L2")

    def test_profile_etudiant_creation(self, student_user, annee, filiere, matiere, semestre, niveau, matiere_commune):
        """Test ProfileEtudiant creation and relationships."""
        profile = ProfileEtudiant.objects.create(
            etudiant=student_user.etudiant_profile,
            annee=annee,
            filiere=filiere,
            matiere=matiere,
            semestre=semestre,
            niveau=niveau,
            matiere_commune=matiere_commune
        )
        assert profile.etudiant == student_user.etudiant_profile
        assert profile.annee == annee
        assert profile.filiere == filiere
        assert profile.matiere == matiere
        assert profile.semestre == semestre
        assert profile.niveau == niveau
        assert profile.matiere_commune == matiere_commune

# Form Tests (Updated for dropdowns)
@pytest.mark.django_db
class TestForms:
    def test_student_profile_form_valid(self, annee, niveau, filiere, semestre, matiere, matiere_commune):
        """Test StudentProfileForm with valid dropdown selections."""
        data = {
            'annee': annee.id,
            'niveau': niveau.id,
            'filiere': filiere.id,
            'semestre': semestre.id,
            'matiere': matiere.id,
            'matiere_commune': matiere_commune.id,
        }
        form = StudentProfileForm(data=data)
        assert form.is_valid()

    def test_student_profile_form_invalid_missing_required(self):
        """Test StudentProfileForm with missing required dropdown selections."""
        data = {
            'annee': '',  # Optional
            'niveau': '',  # Required
            'filiere': '',  # Required
            'semestre': '',  # Required
            'matiere': '',  # Required
            'matiere_commune': '',  # Optional
        }
        form = StudentProfileForm(data=data)
        assert not form.is_valid()
        assert 'niveau' in form.errors
        assert 'filiere' in form.errors
        assert 'semestre' in form.errors
        assert 'matiere' in form.errors

    def test_student_profile_form_invalid_ids(self, annee):
        """Test StudentProfileForm with invalid foreign key IDs in dropdowns."""
        data = {
            'annee': annee.id,
            'niveau': 999,
            'filiere': 999,
            'semestre': 999,
            'matiere': 999,
            'matiere_commune': 999,
        }
        form = StudentProfileForm(data=data)
        assert not form.is_valid()
        assert 'niveau' in form.errors
        assert 'filiere' in form.errors
        assert 'semestre' in form.errors
        assert 'matiere' in form.errors
        assert 'matiere_commune' in form.errors

    def test_student_profile_form_save(self, student_user, annee, niveau, filiere, semestre, matiere, matiere_commune):
        """Test StudentProfileForm saving to database with dropdown selections."""
        data = {
            'annee': annee.id,
            'niveau': niveau.id,
            'filiere': filiere.id,
            'semestre': semestre.id,
            'matiere': matiere.id,
            'matiere_commune': matiere_commune.id,
        }
        form = StudentProfileForm(data=data)
        assert form.is_valid()
        profile = form.save(commit=False)
        profile.etudiant = student_user.etudiant_profile
        profile.save()
        assert ProfileEtudiant.objects.filter(etudiant=student_user.etudiant_profile).exists()

# View Tests (Updated for home_etudiant)
@pytest.mark.django_db
class TestViews:
    def test_home_etudiant_view_get_authenticated(self, client, student_user):
        """Test GET request to home_etudiant view for authenticated user."""
        client.login(username='student', password='password')
        response = client.get(reverse('roles:home_etudiant'))
        assert response.status_code == 200
        assert 'user' in response.context
        assert response.context['user'] == student_user
        assert 'form' in response.context
        assert isinstance(response.context['form'], StudentProfileForm)
        assert 'matiere_data' in response.context
        assert 'matiere_commune_data' in response.context
        assert response.templates[0].name == 'roles/etudiant_dashboard.html'

    def test_home_etudiant_view_post_valid(self, client, student_user, annee, niveau, filiere, semestre, matiere, matiere_commune):
        """Test POST request to home_etudiant with valid form data."""
        client.login(username='student', password='password')
        data = {
            'annee': annee.id,
            'niveau': niveau.id,
            'filiere': filiere.id,
            'semestre': semestre.id,
            'matiere': matiere.id,
            'matiere_commune': matiere_commune.id,
        }
        response = client.post(reverse('roles:home_etudiant'), data=data)
        assert response.status_code == 302  # Assuming redirect after successful profile creation
        assert ProfileEtudiant.objects.filter(etudiant=student_user.etudiant_profile).exists()

    def test_home_etudiant_view_post_invalid(self, client, student_user):
        """Test POST request to home_etudiant with invalid form data."""
        client.login(username='student', password='password')
        data = {
            'annee': '',
            'niveau': 999,
            'filiere': '',
            'semestre': '',
            'matiere': '',
            'matiere_commune': '',
        }
        response = client.post(reverse('roles:home_etudiant'), data=data)
        assert response.status_code == 200
        assert 'form' in response.context
        assert not response.context['form'].is_valid()

    def test_home_etudiant_view_anonymous(self, client):
        """Test home_etudiant view denies anonymous access."""
        response = client.get(reverse('roles:home_etudiant'))
        assert response.status_code == 302
        assert response.url.startswith('/signin/')  # Updated to reflect LOGIN_URL

    def test_home_etudiant_matiere_data(self, client, student_user, filiere, semestre, niveau, matiere):
        """Test matiere_data structure in home_etudiant view."""
        client.login(username='student', password='password')
        matiere2 = Matiere.objects.create(
            nom_matiere="Physique", course_code="PHYS101",
            filiere=filiere, semestre=semestre, niveau=niveau
        )
        response = client.get(reverse('roles:home_etudiant'))
        matiere_data = json.loads(response.context['matiere_data'])
        key = f"{filiere.id}_{semestre.id}_{niveau.id}"
        assert key in matiere_data
        assert len(matiere_data[key]) == 2
        assert matiere_data[key][0]['id'] == matiere.id
        assert matiere_data[key][0]['nom'] == "Mathématiques"
        assert matiere_data[key][1]['id'] == matiere2.id
        assert matiere_data[key][1]['nom'] == "Physique"

    def test_home_etudiant_matiere_commune_data(self, client, student_user, filiere, semestre, niveau, matiere_commune):
        """Test matiere_commune_data structure in home_etudiant view."""
        client.login(username='student', password='password')
        matiere_commune2 = MatiereCommune.objects.create(
            nom_matiere_commune="Français", course_code="FR101",
            filiere=filiere, semestre=semestre, niveau=niveau
        )
        response = client.get(reverse('roles:home_etudiant'))
        matiere_commune_data = json.loads(response.context['matiere_commune_data'])
        key = f"{filiere.id}_{semestre.id}_{niveau.id}"
        assert key in matiere_commune_data
        assert len(matiere_commune_data[key]) == 2
        assert matiere_commune_data[key][0]['id'] == matiere_commune.id
        assert matiere_commune_data[key][0]['nom'] == "Anglais"
        assert matiere_commune_data[key][1]['id'] == matiere_commune2.id
        assert matiere_commune_data[key][1]['nom'] == "Français"