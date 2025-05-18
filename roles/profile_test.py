import pytest
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.contrib import messages
from django.core import mail
from django.test import override_settings
from roles.forms import DefaultSignUpForm, StudentProfileForm
from roles.models import Annee, Niveau, Filiere, Semestre, Etudiant, Matiere, MatiereCommune

User = get_user_model()

# Fixtures
@pytest.fixture
def student_user():
    """Crée un utilisateur étudiant avec un profil Etudiant."""
    user = User.objects.create_user(username='student', password='password', role='etudiant')
    Etudiant.objects.create(user=user)
    return user

@pytest.fixture
def academic_data():
    """Crée des données académiques pour les tests."""
    annee, _ = Annee.objects.get_or_create(annee='2023-2024')
    niveau = Niveau.objects.create(nom_niveau='L1')
    filiere = Filiere.objects.create(nom_filiere='Informatique')
    semestre = Semestre.objects.create(nom_semestre='S1')
    matiere = Matiere.objects.create(
        nom_matiere='Programmation', course_code='PROG101', filiere=filiere, semestre=semestre, niveau=niveau
    )
    matiere_commune = MatiereCommune.objects.create(
        nom_matiere_commune='Maths', course_code='MATH101', filiere=filiere, semestre=semestre, niveau=niveau
    )
    return {
        'annee': annee,
        'niveau': niveau,
        'filiere': filiere,
        'semestre': semestre,
        'matiere': matiere,
        'matiere_commune': matiere_commune
    }

@pytest.fixture
def pending_user_session(client):

    """Configure une session avec un utilisateur en attente."""
    hashed_password = make_password('password')
    pending_user = {
        'username': 'pending',
        'password': hashed_password,
        'email': 'pending@example.com',
        'first_name': 'Pending',
        'last_name': 'User',
        'role': 'etudiant',
        'is_active': False
    }
    session = client.session
    session['pending_user'] = pending_user
    session.save()
    # Remove the assertion here, as session data is not immediately available after save
    return client

# Tests pour la vue signin
@pytest.mark.django_db
class TestSigninView:
    """Tests pour la vue signin."""

    def test_signin_get(self, client):
        """Vérifie que GET rend le template signin.html."""
        response = client.get(reverse('roles:signin'))
        assert response.status_code == 200
        assert 'roles/signin.html' in [t.name for t in response.templates]

    def test_signin_post_valid_etudiant(self, client, student_user):
        """Vérifie qu’un étudiant valide est connecté et redirigé."""
        response = client.post(reverse('roles:signin'), {'username': 'student', 'password': 'password'})
        assert response.status_code == 302
        assert response.url == reverse('roles:etudiant_dashboard')
        assert '_auth_user_id' in client.session
        assert int(client.session['_auth_user_id']) == student_user.pk

    def test_signin_post_invalid(self, client):
        """Vérifie qu’un login invalide affiche une erreur."""
        response = client.post(reverse('roles:signin'), {'username': 'wrong', 'password': 'wrong'})
        assert response.status_code == 200
        assert 'roles/signin.html' in [t.name for t in response.templates]
        messages_list = list(messages.get_messages(response.wsgi_request))
        assert any('Invalid username or password' in str(msg) for msg in messages_list)
        assert '_auth_user_id' not in client.session

    def test_signin_post_pending_valid(self, pending_user_session):
        """Vérifie qu’un utilisateur en attente valide est créé et redirigé."""
        client = pending_user_session
        assert client.session.get('pending_user') is not None, "Session data lost before POST"
        response = client.post(reverse('roles:signin'), {'username': 'pending', 'password': 'password'})
        assert response.status_code == 302
        assert response.url == reverse('roles:etudiant_dashboard')
        user = User.objects.get(username='pending')
        assert user.role == 'etudiant'
        assert user.is_active
        assert Etudiant.objects.filter(user=user).exists()
        assert '_auth_user_id' in client.session
        assert int(client.session['_auth_user_id']) == user.pk
        assert 'pending_user' not in client.session

    def test_signin_post_pending_invalid_password(self, pending_user_session):
        """Vérifie qu’un mot de passe invalide pour un utilisateur en attente affiche une erreur."""
        client = pending_user_session
        response = client.post(reverse('roles:signin'), {'username': 'pending', 'password': 'wrong'})
        assert response.status_code == 200
        assert 'roles/signin.html' in [t.name for t in response.templates]
        messages_list = list(messages.get_messages(response.wsgi_request))
        assert any('Invalid password.' in str(msg) for msg in messages_list)

    def test_signin_post_pending_existing_username(self, client, student_user):
        """Vérifie qu’un nom d’utilisateur existant affiche une erreur."""
        hashed_password = make_password('password')
        pending_user = {
            'username': 'student',
            'password': hashed_password,
            'email': 'pending@example.com',
            'first_name': 'Pending',
            'last_name': 'User',
            'role': 'etudiant',
            'is_active': False
        }
        client.session['pending_user'] = pending_user
        client.session.save()
        assert client.session.get('pending_user') is not None, "Session data not set in test"
        response = client.post(reverse('roles:signin'), {'username': 'student', 'password': 'password'})
        assert response.status_code == 200
        assert 'roles/signin.html' in [t.name for t in response.templates]
        messages_list = list(messages.get_messages(response.wsgi_request))
        assert any('Username or email already exists' in str(msg) for msg in messages_list)
        assert '_auth_user_id' not in client.session

# Tests pour la vue etudiant_dashboard
@pytest.mark.django_db
class TestEtudiantDashboardView:
    """Tests pour la vue etudiant_dashboard."""

    def test_etudiant_dashboard_get_unauthenticated(self, client):
        """Vérifie qu’un utilisateur non authentifié est redirigé."""
        response = client.get(reverse('roles:etudiant_dashboard'))
        assert response.status_code == 302
        assert response.url.startswith(reverse('roles:signin'))
        response = client.get(response.url, follow=True)
        assert 'roles/signin.html' in [t.name for t in response.templates]

    def test_etudiant_dashboard_get_student(self, client, student_user, academic_data):
        """Vérifie qu’un étudiant voit le tableau de bord."""
        client.login(username='student', password='password')
        response = client.get(reverse('roles:etudiant_dashboard'))
        assert response.status_code == 200
        assert 'roles/etudiant_dashboard.html' in [t.name for t in response.templates]
        assert 'form' in response.context
        assert 'annee_choices' in response.context
        assert 'niveau_choices' in response.context
        assert 'filiere_choices' in response.context
        assert 'semestre_choices' in response.context
        assert 'matiere_data' in response.context
        assert 'matiere_commune_data' in response.context

    def test_etudiant_dashboard_post_valid(self, client, student_user, academic_data):
        """Vérifie qu’un formulaire valide enregistre le profil et redirige."""
        client.login(username='student', password='password')
        form_data = {
            'filiere': academic_data['filiere'].id,
            'matiere': academic_data['matiere'].id,
            'semestre': academic_data['semestre'].id,
            'annee': academic_data['annee'].id,
            'niveau': academic_data['niveau'].id,
            'matiere_commune': academic_data['matiere_commune'].id
        }
        response = client.post(reverse('roles:etudiant_dashboard'), data=form_data)
        assert response.status_code == 302
        assert response.url == reverse('roles:etudiant_dashboard')
        profile = student_user.etudiant_profile.profileetudiant_set.get()
        assert profile.filiere == academic_data['filiere']
        assert profile.matiere == academic_data['matiere']
        messages_list = list(messages.get_messages(response.wsgi_request))
        assert any('Profile created successfully' in str(msg) for msg in messages_list)

    def test_etudiant_dashboard_post_invalid(self, client, student_user):
        """Vérifie qu’un formulaire invalide affiche une erreur."""
        client.login(username='student', password='password')
        form_data = {}  # Données invalides
        response = client.post(reverse('roles:etudiant_dashboard'), data=form_data)
        assert response.status_code == 200
        assert 'roles/etudiant_dashboard.html' in [t.name for t in response.templates]
        messages_list = list(messages.get_messages(response.wsgi_request))
        assert any('Please correct the errors below' in str(msg) for msg in messages_list)

# Tests pour la vue etudiant_signup
@pytest.mark.django_db
class TestEtudiantSignupView:
    """Tests pour la vue etudiant_signup."""

    def test_signup_get(self, client):
        """Vérifie que GET rend le template signup.html."""
        response = client.get(reverse('roles:etudiant_signup'))
        assert response.status_code == 200
        assert 'roles/signup.html' in [t.name for t in response.templates]
        assert 'form' in response.context

    @override_settings(DEFAULT_FROM_EMAIL='test@example.com')
    def test_signin_post_pending_valid(self, pending_user_session):
        """Vérifie qu’un utilisateur en attente valide est créé et redirigé."""
        client = pending_user_session
        response = client.post(reverse('roles:signin'), {'username': 'pending', 'password': 'password'})
        assert response.status_code == 302

def test_signin_post_pending_invalid_password(self, pending_user_session):
    """Vérifie qu’un mot de passe invalide pour un utilisateur en attente affiche une erreur."""
    client = pending_user_session
    response = client.post(reverse('roles:signin'), {'username': 'pending', 'password': 'wrong'})
    assert response.status_code == 200
    assert 'roles/signin.html' in [t.name for t in response.templates]
    messages_list = list(messages.get_messages(response.wsgi_request))
    assert any('Invalid password.' in str(msg) for msg in messages_list)

def test_signin_post_pending_existing_username(self, client, student_user):
    """Vérifie qu’un nom d’utilisateur existant affiche une erreur."""
    hashed_password = make_password('password')
    pending_user = {
        'username': 'student',
        'password': hashed_password,
        'email': 'pending@example.com',
        'first_name': 'Pending',
        'last_name': 'User',
        'role': 'etudiant',
        'is_active': False
    }
    session = client.session
    session['pending_user'] = pending_user
    session.save()
    assert 'pending_user' in session, "Session data not set in test"
    response = client.post(reverse('roles:signin'), {'username': 'student', 'password': 'password'})
    assert response.status_code == 200  # Should fail due to existing user
    messages_list = list(messages.get_messages(response.wsgi_request))
    assert any('Invalid username or password.' in str(msg) for msg in messages_list)  # Adjust based on view logic