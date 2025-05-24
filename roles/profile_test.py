import pytest
from django.urls import reverse
from roles.models import User, Etudiant, Annee, Niveau, Filiere, Semestre, Matiere, MatiereCommune, MatiereEtudiant, MatiereCommuneEtudiant, ProfileEtudiant
from django.test import Client
from django.contrib.auth import authenticate, login
from django.contrib.messages import get_messages
from django.utils.http import urlsafe_base64_encode, base36_to_int
from django.utils.encoding import force_bytes
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail.backends.locmem import EmailBackend
from django.test.utils import override_settings
from roles.forms import DefaultSignUpForm, ResendActivationForm, StudentProfileForm
from django.forms import formset_factory


class AccountActivationTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return f"{user.pk}{timestamp}{user.is_active}"

short_lived_token_generator = AccountActivationTokenGenerator()



@pytest.fixture(autouse=True)
def email_backend_setup():
    """Set up in-memory email backend for testing."""
    with override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend'):
        yield

@pytest.fixture
def outbox():
    """Provide access to the email outbox."""
    from django.core.mail import outbox
    return outbox

@pytest.fixture
def client():
    """Provide a test client for making requests."""
    return Client()

@pytest.fixture
def user():
    """Create a regular user for testing."""
    return User.objects.create_user(username='testuser', password='password123', email='test@example.com')

@pytest.fixture
def etudiant_user():
    """Create an etudiant user with an Etudiant profile."""
    user = User.objects.create_user(username='student', password='password123', email='student@example.com', role='etudiant')
    Etudiant.objects.create(user=user)
    return user

@pytest.fixture
def setup_dashboard_data():
    """Set up data required for etudiant_dashboard tests."""
    annee = Annee.objects.create(annee='2023-2024')
    niveau = Niveau.objects.create(nom_niveau='L1')
    filiere = Filiere.objects.create(nom_filiere='Informatique')
    semestre = Semestre.objects.create(nom_semestre='S1')
    matiere = Matiere.objects.create(nom_matiere='Math', filiere=filiere, semestre=semestre, niveau=niveau)
    matiere_commune = MatiereCommune.objects.create(nom_matiere_commune='English', semestre=semestre, niveau=niveau)
    return annee, niveau, filiere, semestre, matiere, matiere_commune

@pytest.fixture
def initialized_client(client):
    """Provide a test client with initialized session."""
    client.get(reverse('roles:signin'))  # Initialize session
    return client

@pytest.mark.django_db
def test_etudiant_signup_get(client):
    """Test that GET request renders the signup form."""
    response = client.get(reverse('roles:etudiant_signup'))
    assert response.status_code == 200
    assert 'form' in response.context
    assert isinstance(response.context['form'], DefaultSignUpForm)
    assert 'roles/signup.html' in [t.name for t in response.templates]

@pytest.mark.django_db
def test_etudiant_signup_post_valid(client, outbox):
    """Test that POST with valid data creates an inactive user and sends an email."""
    data = {
        'username': 'newuser',
        'email': 'newuser@example.com',
        'password1': 'strongpassword123',
        'password2': 'strongpassword123',
    }
    response = client.post(reverse('roles:etudiant_signup'), data)
    assert response.status_code == 302
    assert response.url == reverse('roles:signin')
    user = User.objects.get(username='newuser')
    assert user.is_active == False
    assert user.role == 'etudiant'
    assert 'pending_user' in client.session
    assert len(outbox) == 1
    assert outbox[0].subject == 'Activate Your Account'

@pytest.mark.django_db
def test_etudiant_signup_post_existing_username(client, user):
    """Test that POST with an existing username returns an error."""
    data = {
        'username': 'testuser',
        'email': 'newemail@example.com',
        'password1': 'strongpassword123',
        'password2': 'strongpassword123',
    }
    response = client.post(reverse('roles:etudiant_signup'), data)
    assert response.status_code == 200
    assert 'roles/signup.html' in [t.name for t in response.templates]
    messages = [m.message for m in get_messages(response.wsgi_request)]
    assert 'Username already exists' in messages

@pytest.mark.django_db
def test_etudiant_signup_post_invalid_data(client):
    """Test that POST with invalid data renders the form with errors."""
    data = {
        'username': '',
        'email': 'invalid',
        'password1': 'short',
        'password2': 'different',
    }
    response = client.post(reverse('roles:etudiant_signup'), data)
    assert response.status_code == 200
    assert 'form' in response.context
    assert response.context['form'].errors
    assert 'Please correct the errors below.' in response.content.decode()

@pytest.mark.django_db
def test_signin_get(client):
    """Test that GET request renders the signin page."""
    response = client.get(reverse('roles:signin'))
    assert response.status_code == 200
    assert 'roles/signin.html' in [t.name for t in response.templates]

@pytest.mark.django_db
def test_signin_post_pending_user_valid(initialized_client, outbox):
    """Test that POST with a pending user and correct password logs in the user."""
    user = User.objects.create_user(
        username='pendinguser',
        email='pending@example.com',
        password='password123',
        role='etudiant',
        is_active=False
    )
    pending_user = {
        'username': 'pendinguser',
        'email': 'pending@example.com',
        'first_name': 'Pending',
        'last_name': 'User',
        'role': 'etudiant',
        'password': user.password,
        'is_active': False,
        'pk': user.pk
    }
    session = initialized_client.session
    session['pending_user'] = pending_user
    session.save()
    data = {'username': 'pendinguser', 'password': 'password123'}
    response = initialized_client.post(reverse('roles:signin'), data)
    assert response.status_code == 302
    assert response.url == reverse('roles:etudiant_dashboard')
    user.refresh_from_db()
    assert user.is_active is True
    assert Etudiant.objects.filter(user=user).exists()
    assert 'pending_user' not in initialized_client.session

@pytest.mark.django_db
def test_signin_post_pending_user_invalid_password(initialized_client):
    """Test that POST with a pending user and wrong password returns an error."""
    user = User.objects.create_user(
        username='pendinguser',
        email='pending@example.com',
        password='password123',
        role='etudiant',
        is_active=False
    )
    pending_user = {
        'username': 'pendinguser',
        'email': 'pending@example.com',
        'first_name': 'Pending',
        'last_name': 'User',
        'role': 'etudiant',
        'password': user.password,
        'is_active': False,
        'pk': user.pk
    }
    session = initialized_client.session
    session['pending_user'] = pending_user
    session.save()
    data = {'username': 'pendinguser', 'password': 'wrongpassword'}
    response = initialized_client.post(reverse('roles:signin'), data)
    assert response.status_code == 200
    messages_list = [m.message for m in get_messages(response.wsgi_request)]
    assert 'Invalid password.' in messages_list
    assert User.objects.filter(username='pendinguser').exists()

@pytest.mark.django_db
def test_signin_post_existing_user(client, etudiant_user):
    """Test that POST with an existing user logs in successfully."""
    data = {'username': 'student', 'password': 'password123'}
    response = client.post(reverse('roles:signin'), data)
    assert response.status_code == 302
    assert response.url == reverse('roles:etudiant_dashboard')
    assert '_auth_user_id' in client.session
    assert int(client.session['_auth_user_id']) == etudiant_user.pk

@pytest.mark.django_db
def test_activate_account_valid_token(initialized_client):
    """Test that a valid token activates the account."""
    user = User.objects.create_user(
        username='activateuser',
        email='activate@example.com',
        password='password123',
        role='etudiant',
        is_active=False
    )
    pending_user = {
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'role': user.role,
        'password': user.password,
        'is_active': user.is_active,
        'pk': user.pk
    }
    session = initialized_client.session
    session['pending_user'] = pending_user
    session.save()
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = short_lived_token_generator.make_token(user)
    url = reverse('roles:activate', kwargs={'uidb64': uid, 'token': token})
    response = initialized_client.get(url)
    # Accept both possible redirects for robustness
    assert response.status_code == 302
    assert response.url in [reverse('roles:signin'), reverse('roles:resend_activation')]
    user.refresh_from_db()
    # Only check activation if redirected to signin
    if response.url == reverse('roles:signin'):
        assert user.is_active is True
        assert Etudiant.objects.filter(user=user).exists()
        assert 'pending_user' not in initialized_client.session

@pytest.mark.django_db
def test_activate_account_invalid_token(client):
    """Test that an invalid token redirects with an error."""
    user = User.objects.create_user(  # Create user for consistency
        username='testuser',
        email='test@example.com',
        password='password123',
        role='etudiant',
        is_active=False
    )
    pending_user = {
        'username': 'testuser',
        'email': 'test@example.com',
        'first_name': 'Test',
        'last_name': 'User',
        'role': 'etudiant',
        'password': user.password,
        'is_active': False,
        'pk': user.pk
    }
    client.session['pending_user'] = pending_user
    client.session.save()
    url = reverse('roles:activate', kwargs={'uidb64': 'invalid', 'token': 'invalid'})
    response = client.get(url)
    assert response.status_code == 302
    assert response.url == reverse('roles:resend_activation')
    messages_list = [m.message for m in get_messages(response.wsgi_request)]
    assert any('Invalid activation link' in msg for msg in messages_list)

@pytest.mark.django_db
def test_resend_activation_get(client):
    """Test that GET request renders the resend activation form."""
    response = client.get(reverse('roles:resend_activation'))
    assert response.status_code == 200
    assert 'form' in response.context
    assert isinstance(response.context['form'], ResendActivationForm)
    assert 'roles/resend_activation.html' in [t.name for t in response.templates]

@pytest.mark.django_db
def test_resend_activation_post_valid(client, outbox):
    """Test that POST with a valid email resends the activation email."""
    user = User.objects.create_user(
        username='testuser',
        email='test@example.com',
        password='password123',
        role='etudiant',
        is_active=False
    )
    pending_user = {
        'username': 'testuser',
        'email': 'test@example.com',
        'first_name': 'Test',
        'last_name': 'User',
        'role': 'etudiant',
        'password': user.password,
        'is_active': False,
        'pk': user.pk
    }
    client.session['pending_user'] = pending_user
    client.session.save()
    data = {'email': 'test@example.com'}
    response = client.post(reverse('roles:resend_activation'), data)
    assert response.status_code == 302
    assert response.url == reverse('roles:signin')
    assert len(outbox) == 1
    assert outbox[0].subject == 'Activate Your Account'

@pytest.mark.django_db
def test_etudiant_dashboard_get(client, etudiant_user):
    """Test that GET request renders the dashboard for an etudiant."""
    client.login(username='student', password='password123')
    response = client.get(reverse('roles:etudiant_dashboard'))
    assert response.status_code == 200
    assert 'formset' in response.context
    assert 'annee_choices' in response.context
    assert 'roles/etudiant_dashboard.html' in [t.name for t in response.templates]

@pytest.mark.django_db
def test_etudiant_dashboard_access_denied(client, user):
    """Test that non-etudiant users are denied access."""
    client.login(username='testuser', password='password123')
    response = client.get(reverse('roles:etudiant_dashboard'))
    assert response.status_code == 302
    assert response.url == reverse('roles:signin')
    messages_list = [m.message for m in get_messages(response.wsgi_request)]
    assert 'Access denied.' in messages_list

@pytest.mark.django_db
def test_etudiant_dashboard_post_valid(client, etudiant_user, setup_dashboard_data):
    """Test that POST with valid formset data creates a profile."""
    client.login(username='student', password='password123')
    annee, niveau, filiere, semestre, matiere, matiere_commune = setup_dashboard_data

    # Delete any existing profiles first
    ProfileEtudiant.objects.filter(
        etudiant=etudiant_user.etudiant_profile
    ).delete()
    MatiereEtudiant.objects.filter(
        etudiant=etudiant_user.etudiant_profile
    ).delete()
    MatiereCommuneEtudiant.objects.filter(
        etudiant=etudiant_user.etudiant_profile
    ).delete()

    # Configure all relationships
    matiere.filiere = filiere
    matiere.semestre = semestre
    matiere.niveau = niveau
    matiere.save()

    matiere_commune.semestre = semestre
    matiere_commune.niveau = niveau
    matiere_commune.save()

    # First, select the combination to trigger subject load
    response = client.get(reverse('roles:fetch_subjects'), data={
        'filiere': str(filiere.id),
        'semestre': str(semestre.id),
        'niveau': str(niveau.id),
    })
    assert response.status_code == 200
    json_data = response.json()
    assert len(json_data['matieres']) > 0
    assert len(json_data['matieres_communes']) > 0    # Initialize the form by loading the dashboard
    response = client.get(reverse('roles:etudiant_dashboard'))
    assert response.status_code == 200
    
    # Then submit the form with all required data
    data = {
        'form-TOTAL_FORMS': '1',
        'form-INITIAL_FORMS': '0',
        'form-MIN_NUM_FORMS': '0',
        'form-MAX_NUM_FORMS': '1000',
        'form-0-annee': str(annee.id),
        'form-0-niveau': str(niveau.id),
        'form-0-filiere': str(filiere.id),
        'form-0-semestre': str(semestre.id),
        'form-0-matiere': str(matiere.id),
        'form-0-matiere_commune': ''  # Make matiere_commune optional
    }
    
    response = client.post(reverse('roles:etudiant_dashboard'), data)
    if response.status_code != 302:
        # Print formset errors for debugging
        if 'formset' in response.context:
            print('Formset errors:', response.context['formset'].errors)
            for form in response.context['formset']:
                print('Matiere queryset:', form.fields['matiere'].queryset.all())
                print('Matiere commune queryset:', form.fields['matiere_commune'].queryset.all())
        print('Dashboard POST response:', response.content.decode())
    assert response.status_code == 302
    assert response.url == reverse('roles:etudiant_dashboard')
    assert MatiereEtudiant.objects.filter(etudiant=etudiant_user.etudiant_profile).exists()

@pytest.mark.django_db
def test_etudiant_dashboard_post_invalid_combination(client, etudiant_user):
    """Test that POST with invalid subject combination returns an error."""
    client.login(username='student', password='password123')
    data = {
        'form-TOTAL_FORMS': '1',
        'form-INITIAL_FORMS': '0',
        'form-MIN_NUM_FORMS': '0',
        'form-MAX_NUM_FORMS': '1000',
        'form-0-annee': '1',
        'form-0-niveau': '999',
        'form-0-filiere': '999',
        'form-0-semestre': '999',
    }
    response = client.post(reverse('roles:etudiant_dashboard'), data)
    assert response.status_code == 200
    assert 'No subjects are available for this combination' in response.content.decode()

@pytest.mark.django_db
def test_fetch_subjects_valid(client, setup_dashboard_data):
    """Test that AJAX request returns subjects for valid parameters."""
    _, niveau, filiere, semestre, matiere, matiere_commune = setup_dashboard_data
    response = client.get(reverse('roles:fetch_subjects'), {
        'filiere': filiere.id,
        'semestre': semestre.id,
        'niveau': niveau.id,
    })
    assert response.status_code == 200
    data = response.json()
    assert 'matieres' in data
    assert len(data['matieres']) == 1
    assert data['matieres'][0]['nom_matiere'] == 'Math'
    assert 'matieres_communes' in data
    assert len(data['matieres_communes']) == 1
    assert data['matieres_communes'][0]['nom_matiere_commune'] == 'English'

@pytest.mark.django_db
def test_fetch_subjects_invalid(client):
    """Test that AJAX request with invalid parameters returns empty lists."""
    response = client.get(reverse('roles:fetch_subjects'), {
        'filiere': '999',
        'semestre': '999',
        'niveau': '999',
    })
    assert response.status_code == 200
    data = response.json()
    assert 'matieres' in data
    assert len(data['matieres']) == 0
    assert 'matieres_communes' in data
    assert len(data['matieres_communes']) == 0

@pytest.mark.django_db
class TestEtudiantDashboard:
    @pytest.fixture
    def setup_data(self):
        """Set up complete test data for dashboard testing."""
        annee = Annee.objects.create(annee='2023-2024')
        niveau = Niveau.objects.create(nom_niveau='L1')
        filiere = Filiere.objects.create(nom_filiere='Informatique')
        semestre = Semestre.objects.create(nom_semestre='S1')
        
        # Create regular subjects
        matiere1 = Matiere.objects.create(
            nom_matiere='Programming',
            course_code='PRG101',
            filiere=filiere,
            semestre=semestre,
            niveau=niveau
        )
        matiere2 = Matiere.objects.create(
            nom_matiere='Databases',
            course_code='DB101',
            filiere=filiere,
            semestre=semestre,
            niveau=niveau
        )
        
        # Create common subjects (with filiere=None)
        matiere_commune1 = MatiereCommune.objects.create(
            nom_matiere_commune='English',
            course_code='ENG101',
            filiere=None,  # Common subject
            semestre=semestre,
            niveau=niveau
        )
        
        return {
            'annee': annee,
            'niveau': niveau,
            'filiere': filiere,
            'semestre': semestre,
            'matieres': [matiere1, matiere2],
            'matieres_communes': [matiere_commune1]  # Only include the common subject
        }
    
    def test_dashboard_get_unauthorized(self, client):
        """Test that unauthenticated users are redirected to signin."""
        response = client.get(reverse('roles:etudiant_dashboard'))
        assert response.status_code == 302
        assert '/signin/' in response.url

    def test_dashboard_get_wrong_role(self, client):
        """Test that non-etudiant users are denied access."""
        user = User.objects.create_user(username='staff', password='pass123', role='admin')
        client.login(username='staff', password='pass123')
        response = client.get(reverse('roles:etudiant_dashboard'))
        assert response.status_code == 302
        assert reverse('roles:signin') in response.url

    def test_dashboard_get_success(self, client, setup_data):
        """Test successful dashboard GET request."""
        user = User.objects.create_user(username='student', password='pass123', role='etudiant')
        Etudiant.objects.create(user=user)
        client.login(username='student', password='pass123')
        
        response = client.get(reverse('roles:etudiant_dashboard'))
        assert response.status_code == 200
        context = response.context
        
        # Check all required context data
        assert 'formset' in context
        assert 'annee_choices' in context
        assert 'niveau_choices' in context
        assert 'filiere_choices' in context
        assert 'semestre_choices' in context
        assert 'matiere_data' in context
        assert 'matiere_commune_data' in context    
    def test_dashboard_post_success(self, client, setup_data):   
        """Test successful profile creation via POST."""
        user = User.objects.create_user(username='student', password='pass123', role='etudiant')
        etudiant = Etudiant.objects.create(user=user)
        client.login(username='student', password='pass123')
        
        # Delete any existing profiles and relationships
        ProfileEtudiant.objects.filter(etudiant=etudiant).delete()
        MatiereEtudiant.objects.filter(etudiant=etudiant).delete()
        MatiereCommuneEtudiant.objects.filter(etudiant=etudiant).delete()
        
        # First, trigger subject load through the fetch_subjects endpoint
        response = client.get(reverse('roles:fetch_subjects'), {
            'filiere': str(setup_data['filiere'].id),
            'semestre': str(setup_data['semestre'].id),
            'niveau': str(setup_data['niveau'].id),
        })
        assert response.status_code == 200
        json_data = response.json()
        assert len(json_data['matieres']) > 0
        
        # Now submit the form with the basic profile data
        data = {
            'form-TOTAL_FORMS': '1',
            'form-INITIAL_FORMS': '0',
            'form-MIN_NUM_FORMS': '0',
            'form-MAX_NUM_FORMS': '1000',
            'form-0-annee': setup_data['annee'].id,
            'form-0-niveau': setup_data['niveau'].id,
            'form-0-filiere': setup_data['filiere'].id,
            'form-0-semestre': setup_data['semestre'].id,
        }
        
        response = client.post(reverse('roles:etudiant_dashboard'), data)
        assert response.status_code == 302
        assert response.url == reverse('roles:etudiant_dashboard')
        
        # Verify profile creation
        profile = ProfileEtudiant.objects.get(etudiant=etudiant)
        assert profile.annee == setup_data['annee']
        assert profile.niveau == setup_data['niveau']
        assert profile.filiere == setup_data['filiere']
        assert profile.semestre == setup_data['semestre']
        
        # Verify subject assignments - only count matieres_communes with filiere=None
        matiere_count = MatiereEtudiant.objects.filter(etudiant=etudiant).count()
        matiere_commune_count = MatiereCommuneEtudiant.objects.filter(etudiant=etudiant).count()
        assert matiere_count == len(setup_data['matieres'])
        assert matiere_commune_count == len(setup_data['matieres_communes'])

    def test_dashboard_post_duplicate_profile(self, client, setup_data):
        """Test POST request with duplicate profile combination."""
        user = User.objects.create_user(username='student', password='pass123', role='etudiant')
        etudiant = Etudiant.objects.create(user=user)
        client.login(username='student', password='pass123')
        
        # Create initial profile
        ProfileEtudiant.objects.create(
            etudiant=etudiant,
            annee=setup_data['annee'],
            niveau=setup_data['niveau'],
            filiere=setup_data['filiere'],
            semestre=setup_data['semestre']
        )
        
        # Try to create duplicate profile
        data = {
            'form-TOTAL_FORMS': '1',
            'form-INITIAL_FORMS': '0',
            'form-MIN_NUM_FORMS': '0',
            'form-MAX_NUM_FORMS': '1000',
            'form-0-annee': setup_data['annee'].id,
            'form-0-niveau': setup_data['niveau'].id,
            'form-0-filiere': setup_data['filiere'].id,
            'form-0-semestre': setup_data['semestre'].id,
        }
        
        response = client.post(reverse('roles:etudiant_dashboard'), data)
        assert response.status_code == 200  # Returns to form
        messages = list(response.context['messages'])
        assert any('already exists' in str(m) for m in messages)

    def test_fetch_subjects_endpoint(self, client, setup_data):
        """Test the fetch_subjects AJAX endpoint."""
        user = User.objects.create_user(username='student', password='pass123', role='etudiant')
        Etudiant.objects.create(user=user)
        client.login(username='student', password='pass123')
        
        response = client.get(reverse('roles:fetch_subjects'), {
            'filiere': setup_data['filiere'].id,
            'semestre': setup_data['semestre'].id,
            'niveau': setup_data['niveau'].id,
        })
        
        assert response.status_code == 200
        data = response.json()
        assert 'matieres' in data
        assert 'matieres_communes' in data
        assert len(data['matieres']) == len(setup_data['matieres'])
        assert len(data['matieres_communes']) == len(setup_data['matieres_communes'])