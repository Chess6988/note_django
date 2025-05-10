from pyexpat.errors import messages
import pytest
from django.test import Client
from django.urls import reverse
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from django.db import IntegrityError
import json
from roles.models import User, Etudiant, Annee, Filiere, Semestre, Niveau, Matiere, MatiereCommune, ProfileEtudiant
from roles.forms import StudentProfileForm

# Enable database access for all tests
pytestmark = pytest.mark.django_db

# Fixtures for reusable test data
@pytest.fixture
def client():
    """Provide a Django test client."""
    return Client()

@pytest.fixture
def etudiant_user():
    """Create an etudiant user with Etudiant profile."""
    user = User.objects.create_user(
        username="etudiant1",
        email="etudiant1@example.com",
        password="etudiantpass123",
        role="etudiant",
        first_name="Etudiant",
        last_name="One"
    )
    Etudiant.objects.create(user=user)
    return user

@pytest.fixture
def annee():
    """Create an Annee instance."""
    return Annee.objects.create(annee="2023-2024")

@pytest.fixture
def filiere():
    """Create a Filiere instance."""
    return Filiere.objects.create(nom_filiere="Computer Science")

@pytest.fixture
def semestre():
    """Create a Semestre instance."""
    return Semestre.objects.create(nom_semestre="Semester 1")

@pytest.fixture
def niveau():
    """Create a Niveau instance."""
    return Niveau.objects.create(nom_niveau="First Year")

@pytest.fixture
def matiere(filiere: Filiere, semestre: Semestre, niveau: Niveau):
    """Create a Matiere instance."""
    return Matiere.objects.create(
        nom_matiere="Mathematics",
        course_code="MATH101",
        filiere=filiere,
        semestre=semestre,
        niveau=niveau
    )

@pytest.fixture
def matiere_commune(filiere: Filiere, semestre: Semestre, niveau: Niveau):
    """Create a MatiereCommune instance."""
    return MatiereCommune.objects.create(
        nom_matiere_commune="English",
        course_code="ENG101",
        filiere=filiere,
        semestre=semestre,
        niveau=niveau
    )

# Model Tests
class TestModels:
    def test_user_creation(self, etudiant_user: User):
        """Test User model creation and str method."""
        assert User.objects.count() == 1
        assert str(etudiant_user) == "Etudiant One (etudiant)"
        assert etudiant_user.get_redirect_url() == "/etudiant/dashboard/"

    def test_etudiant_creation(self, etudiant_user: User):
        """Test Etudiant model creation and str method."""
        assert Etudiant.objects.count() == 1
        assert str(etudiant_user.etudiant_profile) == "Etudiant Profile for Etudiant One (etudiant)"

    def test_annee_current_academic_year(self):
        """Test Annee.get_current_academic_year method."""
        annee = Annee.get_current_academic_year()
        assert annee.annee.startswith(str(timezone.now().year)) or annee.annee.startswith(str(timezone.now().year - 1))
        assert Annee.objects.count() == 1
        assert str(annee) == annee.annee

    def test_filiere_creation(self, filiere: Filiere):
        """Test Filiere model creation and str method."""
        assert Filiere.objects.count() == 1
        assert str(filiere) == "Computer Science"

    def test_semestre_creation(self, semestre: Semestre):
        """Test Semestre model creation and str method."""
        assert Semestre.objects.count() == 1
        assert str(semestre) == "Semester 1"

    def test_niveau_creation(self, niveau: Niveau):
        """Test Niveau model creation and str method."""
        assert Niveau.objects.count() == 1
        assert str(niveau) == "First Year"

    def test_matiere_creation(self, matiere: Matiere):
        """Test Matiere creation and str method."""
        assert Matiere.objects.count() == 1
        assert str(matiere) == "Mathematics"
        with pytest.raises(IntegrityError):
            Matiere.objects.create(
                nom_matiere="Physics",
                course_code="MATH101",  # Duplicate course_code
                filiere=matiere.filiere,
                semestre=matiere.semestre,
                niveau=matiere.niveau
            )

    def test_matiere_commune_creation(self, matiere_commune: MatiereCommune):
        """Test MatiereCommune creation and str method."""
        assert MatiereCommune.objects.count() == 1
        assert str(matiere_commune) == "English"

    def test_profile_etudiant_creation(self, etudiant_user: User, filiere: Filiere, semestre: Semestre, niveau: Niveau, matiere: Matiere, annee: Annee):
        """Test ProfileEtudiant creation and unique_together constraint."""
        profile = ProfileEtudiant.objects.create(
            etudiant=etudiant_user.etudiant_profile,
            filiere=filiere,
            semestre=semestre,
            niveau=niveau,
            matiere=matiere,
            annee=annee
        )
        assert ProfileEtudiant.objects.count() == 1
        with pytest.raises(IntegrityError):
            ProfileEtudiant.objects.create(
                etudiant=etudiant_user.etudiant_profile,
                filiere=filiere,
                semestre=semestre,
                niveau=niveau,
                matiere=matiere,
                annee=annee
            )  # Violates unique_together

# Form Tests
class TestStudentProfileForm:
    def test_form_valid_submission(self, etudiant_user: User, filiere: Filiere, semestre: Semestre, niveau: Niveau, matiere: Matiere, matiere_commune: MatiereCommune, annee: Annee):
        """Test StudentProfileForm with valid data."""
        form_data = {
            'annee': annee.id,
            'filiere': filiere.id,
            'semestre': semestre.id,
            'niveau': niveau.id,
            'matiere': matiere.id,
            'matiere_commune': matiere_commune.id
        }
        form = StudentProfileForm(data=form_data)
        assert form.is_valid()
        profile = form.save(commit=False)
        profile.etudiant = etudiant_user.etudiant_profile
        profile.save()
        assert ProfileEtudiant.objects.count() == 1

    def test_form_invalid_missing_required(self):
        """Test StudentProfileForm with missing required fields."""
        form_data = {
            'annee': '',
            'filiere': '',
            'semestre': '',
            'niveau': '',
            'matiere': ''
        }
        form = StudentProfileForm(data=form_data)
        assert not form.is_valid()
        assert 'annee' in form.errors
        assert 'filiere' in form.errors
        assert 'semestre' in form.errors
        assert 'niveau' in form.errors
        assert 'matiere' in form.errors

    def test_form_dynamic_queryset(self, filiere: Filiere, semestre: Semestre, niveau: Niveau, matiere: Matiere, matiere_commune: MatiereCommune):
        """Test dynamic queryset filtering in StudentProfileForm."""
        form_data = {
            'filiere': filiere.id,
            'semestre': semestre.id,
            'niveau': niveau.id
        }
        form = StudentProfileForm(data=form_data)
        assert form.fields['matiere'].queryset.count() == 1
        assert form.fields['matiere'].queryset.first().nom_matiere == "Mathematics"
        assert form.fields['matiere_commune'].queryset.count() == 1
        assert form.fields['matiere_commune'].queryset.first().nom_matiere_commune == "English"

    def test_form_no_queryset_when_invalid_ids(self):
        """Test form queryset when filiere, semestre, or niveau IDs are invalid."""
        form_data = {
            'filiere': 999,  # Non-existent ID
            'semestre': 999,
            'niveau': 999
        }
        form = StudentProfileForm(data=form_data)
        assert form.fields['matiere'].queryset.count() == 0
        assert form.fields['matiere_commune'].queryset.count() == 0

# View Tests
class TestSigninView:
    def test_signin_get(self, client: Client):
        """Test signin view GET request renders template."""
        response = client.get(reverse('roles:signin'))
        assert response.status_code == 200
        assert 'roles/signin.html' in [t.name for t in response.templates]

    def test_signin_pending_user_valid(self, client: Client):
        """Test signin for pending user with valid credentials."""
        pending_user = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'first_name': 'New',
            'last_name': 'User',
            'role': 'etudiant',
            'password': make_password('newpass123')
        }
        # Explicitly get the session object and set the data
        session = client.session
        session['pending_user'] = pending_user
        session.save()
        # Verify that the session data is correctly set before the request
        assert client.session.get('pending_user') == pending_user, "Session data not set correctly"
        # Perform the sign-in POST request
        response = client.post(reverse('roles:signin'), {
            'username': 'newuser',
            'password': 'newpass123'
        })
        # Check for redirect (302) and additional assertions
        assert response.status_code == 302
        assert response.url == reverse('roles:etudiant_dashboard')
        assert User.objects.filter(username='newuser').exists()
        assert Etudiant.objects.filter(user__username='newuser').exists()
        assert 'pending_user' not in client.session



    def test_signin_pending_user_invalid_password(self, client: Client):
        """Test signin for pending user with invalid password."""
        pending_user = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'first_name': 'New',
            'last_name': 'User',
            'role': 'etudiant',
            'password': make_password('newpass123')
        }
        session = client.session
        session['pending_user'] = pending_user
        session.save()
        assert client.session.get('pending_user') == pending_user, "Session data not set"
        response = client.post(reverse('roles:signin'), {
            'username': 'newuser',
            'password': 'wrongpass'
        })
        assert response.status_code == 200
        assert 'Invalid password.' in response.content.decode()

    def test_signin_existing_user_valid(self, client: Client, etudiant_user: User):
        """Test signin for existing user with valid credentials."""
        response = client.post(reverse('roles:signin'), {
            'username': 'etudiant1',
            'password': 'etudiantpass123'
        })
        assert response.status_code == 302
        assert response.url == reverse('roles:etudiant_dashboard')

    def test_signin_existing_user_invalid(self, client: Client):
        """Test signin for existing user with invalid credentials."""
        response = client.post(reverse('roles:signin'), {
            'username': 'nonexistent',
            'password': 'wrongpass'
        })
        assert response.status_code == 200
        assert 'Invalid username or password.' in response.content.decode()

class TestCreateProfileView:
    def test_create_profile_get_authenticated(self, client: Client, etudiant_user: User):
        """Test create_profile GET request for authenticated etudiant."""
        client.login(username='etudiant1', password='etudiantpass123')
        response = client.get(reverse('roles:create_profile'))
        assert response.status_code == 200
        assert 'roles/create_profile.html' in [t.name for t in response.templates]

    def test_create_profile_get_unauthenticated(self, client: Client):
        """Test create_profile GET request for unauthenticated user."""
        response = client.get(reverse('roles:create_profile'))
        assert response.status_code == 302
        assert '/signin/' in response.url  # Redirects to login

    def test_create_profile_post_valid(self, client: Client, etudiant_user: User, filiere: Filiere, semestre: Semestre, niveau: Niveau, matiere: Matiere, matiere_commune: MatiereCommune, annee: Annee):
        """Test create_profile POST with valid form data."""
        client.login(username='etudiant1', password='etudiantpass123')
        form_data = {
            'annee': annee.id,
            'filiere': filiere.id,
            'semestre': semestre.id,
            'niveau': niveau.id,
            'matiere': matiere.id,
            'matiere_commune': matiere_commune.id
        }
        response = client.post(reverse('roles:create_profile'), form_data)
        assert response.status_code == 302
        assert response.url == reverse('roles:home_etudiant')
        assert ProfileEtudiant.objects.count() == 1
        profile = ProfileEtudiant.objects.first()
        assert profile.etudiant == etudiant_user.etudiant_profile
        assert profile.matiere == matiere

    def test_create_profile_post_invalid(self, client: Client, etudiant_user: User):
        """Test create_profile POST with invalid form data."""
        client.login(username='etudiant1', password='etudiantpass123')
        form_data = {
            'annee': '',
            'filiere': '',
            'semestre': '',
            'niveau': '',
            'matiere': ''
        }
        response = client.post(reverse('roles:create_profile'), form_data)
        assert response.status_code == 200
        assert 'form' in response.context
        assert not response.context['form'].is_valid()

class TestHomeEtudiantView:
    def test_home_etudiant_get_authenticated(self, client: Client, etudiant_user: User, filiere: Filiere, semestre: Semestre, niveau: Niveau, matiere: Matiere, matiere_commune: MatiereCommune):
        """Test home_etudiant GET request for authenticated etudiant."""
        client.login(username='etudiant1', password='etudiantpass123')
        response = client.get(reverse('roles:home_etudiant'))
        assert response.status_code == 200
        assert 'roles/etudiant_dashboard.html' in [t.name for t in response.templates]
        assert isinstance(response.context['form'], StudentProfileForm)
        assert 'matiere_data' in response.context
        assert 'matiere_commune_data' in response.context
        matiere_data = json.loads(response.context['matiere_data'])
        key = f"{filiere.id}_{semestre.id}_{niveau.id}"
        assert key in matiere_data
        assert any(m['nom'] == 'Mathematics' for m in matiere_data[key])

    def test_home_etudiant_get_unauthenticated(self, client: Client):
        """Test home_etudiant GET request for unauthenticated user."""
        response = client.get(reverse('roles:home_etudiant'))
        assert response.status_code == 302
        assert '/signin/' in response.url

    def test_home_etudiant_post_valid(self, client: Client, etudiant_user: User, filiere: Filiere, semestre: Semestre, niveau: Niveau, matiere: Matiere, matiere_commune: MatiereCommune, annee: Annee):
        """Test home_etudiant POST with valid form data."""
        client.login(username='etudiant1', password='etudiantpass123')
        form_data = {
            'annee': annee.id,
            'filiere': filiere.id,
            'semestre': semestre.id,
            'niveau': niveau.id,
            'matiere': matiere.id,
            'matiere_commune': matiere_commune.id
        }
        response = client.post(reverse('roles:home_etudiant'), form_data)
        assert response.status_code == 302
        assert response.url == reverse('roles:home_etudiant')
        assert ProfileEtudiant.objects.count() == 1

    def test_home_etudiant_post_invalid(self, client: Client, etudiant_user: User):
        """Test home_etudiant POST with invalid form data."""
        client.login(username='etudiant1', password='etudiantpass123')
        form_data = {
            'annee': '',
            'filiere': '',
            'semestre': '',
            'niveau': '',
            'matiere': ''
        }
        response = client.post(reverse('roles:home_etudiant'), form_data)
        assert response.status_code == 200
        assert 'form' in response.context
        assert not response.context['form'].is_valid()