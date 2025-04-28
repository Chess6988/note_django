import pytest
from django.urls import reverse
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta
from django.db import IntegrityError
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from .models import (
    User, Invitation, Etudiant, Enseignant, Admin, Annee, Filiere, Niveau,
    Semestre, Matiere, MatiereCommune, Note, EnseignantAnnee, EtudiantAnnee,
    MatiereEtudiant, MatiereCommuneEtudiant, ProfileEnseignant, ProfileEtudiant
)
from .forms import (
    DefaultSignUpForm, PinForm, ResendActivationForm, InvitationForm, UserAdminForm,
    InvitationAdminForm, AdminAdminForm, EnseignantAdminForm, EtudiantAdminForm,
    MatiereAdminForm, MatiereCommuneAdminForm, NoteAdminForm, ProfileEnseignantAdminForm,
    ProfileEtudiantAdminForm, AnneeForm, FiliereForm, NiveauForm, SemestreForm,
    EnseignantAnneeForm, EtudiantAnneeForm, MatiereEtudiantForm, MatiereCommuneEtudiantForm
)

User = get_user_model()

# ### Fixtures

@pytest.fixture
def superadmin(db):
    """Create a superadmin user."""
    return User.objects.create_superuser(
        username='superadmin', email='superadmin@example.com', password='password', role='superadmin'
    )

@pytest.fixture
def admin_user(db):
    """Create an admin user with Admin profile."""
    user = User.objects.create_user(
        username='admin', email='admin@example.com', password='password', role='admin'
    )
    Admin.objects.create(user=user)
    return user

@pytest.fixture
def enseignant_user(db):
    """Create an enseignant user with Enseignant profile."""
    user = User.objects.create_user(
        username='enseignant', email='enseignant@example.com', password='password', role='enseignant'
    )
    Enseignant.objects.create(user=user)
    return user

@pytest.fixture
def etudiant_user(db):
    """Create an etudiant user with Etudiant profile."""
    user = User.objects.create_user(
        username='etudiant', email='etudiant@example.com', password='password', role='etudiant'
    )
    Etudiant.objects.create(user=user)
    return user

@pytest.fixture
def invitation_admin(db, admin_user):
    """Create an invitation from an admin for an enseignant."""
    unique_suffix = timezone.now().timestamp()
    invitation = Invitation.objects.create(
        role='enseignant', email=f'invited_{unique_suffix}@example.com', inviter=admin_user,
        expires_at=timezone.now() + timedelta(days=1)
    )
    invitation.set_pin('123456')
    return invitation

@pytest.fixture
def academic_data(db):
    """Create basic academic data for related models."""
    annee = Annee.objects.create(annee='2023-2024')
    filiere = Filiere.objects.create(nom_filiere='Informatique')
    niveau = Niveau.objects.create(nom_niveau='L1')
    semestre = Semestre.objects.create(nom_semestre='S1')
    matiere = Matiere.objects.create(
        nom_matiere='Math', course_code='M101', filiere=filiere, semestre=semestre, niveau=niveau
    )
    matiere_commune = MatiereCommune.objects.create(
        nom_matiere_commune='Physics', course_code='P101', filiere=filiere, semestre=semestre, niveau=niveau
    )
    return annee, filiere, niveau, semestre, matiere, matiere_commune

# ### Model Tests

class TestModels:
    """Tests for model creation, validation, and custom methods."""

    @pytest.mark.django_db
    def test_user_creation(self):
        """Test creating a User with valid data."""
        user = User.objects.create_user(
            username='testuser', email='test@example.com', password='password', role='etudiant',
            first_name='Test', last_name='User', phone_number='1234567890'
        )
        assert user.role == 'etudiant'
        assert user.get_redirect_url() == '/etudiant/dashboard/'
        assert user.check_password('password')
        assert str(user) == 'Test User (etudiant)'

    @pytest.mark.django_db
    def test_user_phone_number_validation(self):
        """Test User phone_number validation."""
        user = User(username='testuser', email='test@example.com', phone_number='abc')
        with pytest.raises(ValidationError, match="Phone number must contain only digits."):
            user.clean()

    @pytest.mark.django_db
    def test_invitation_pin(self):
        """Test Invitation PIN setting and checking."""
        invitation = Invitation()
        invitation.set_pin('123456')
        assert invitation.check_pin('123456')
        with pytest.raises(ValidationError, match="PIN must be a 6-digit number."):
            invitation.set_pin('abc')

    @pytest.mark.django_db
    def test_invitation_save_restrictions(self, superadmin, admin_user, enseignant_user):
        """Test Invitation save method restrictions."""
        Invitation.objects.create(
            role='admin', email='admin2@example.com', inviter=superadmin,
            expires_at=timezone.now() + timedelta(days=1)
        )
        Invitation.objects.create(
            role='enseignant', email='teacher2@example.com', inviter=admin_user,
            expires_at=timezone.now() + timedelta(days=1)
        )
        with pytest.raises(ValidationError, match="Admins can only invite teachers."):
            Invitation.objects.create(
                role='admin', email='admin3@example.com', inviter=admin_user,
                expires_at=timezone.now() + timedelta(days=1)
            )
        with pytest.raises(ValidationError, match="Cannot send invitations for etudiant role."):
            Invitation.objects.create(
                role='etudiant', email='student@example.com', inviter=superadmin,
                expires_at=timezone.now() + timedelta(days=1)
            )
        with pytest.raises(ValidationError, match="Only superadmins and admins can send invitations."):
            Invitation.objects.create(
                role='enseignant', email='teacher3@example.com', inviter=enseignant_user,
                expires_at=timezone.now() + timedelta(days=1)
            )

    @pytest.mark.django_db
    def test_matiere_unique_course_code(self, academic_data):
        """Test Matiere course_code uniqueness."""
        _, filiere, niveau, semestre, _, _ = academic_data
        with pytest.raises(IntegrityError):
            Matiere.objects.create(
                nom_matiere='Math2', course_code='M101', filiere=filiere, semestre=semestre, niveau=niveau
            )

    @pytest.mark.django_db
    def test_note_unique_together(self, etudiant_user, academic_data):
        """Test Note unique_together constraint."""
        annee, _, _, _, matiere, _ = academic_data
        Note.objects.create(
            etudiant=etudiant_user.etudiant_profile, matiere=matiere, annee=annee,
            cc_note=10.0, normal_note=15.0, note_final=12.5
        )
        with pytest.raises(IntegrityError):
            Note.objects.create(
                etudiant=etudiant_user.etudiant_profile, matiere=matiere, annee=annee,
                cc_note=12.0, normal_note=16.0, note_final=14.0
            )

# ### Form Tests

class TestForms:
    """Tests for form validation and saving."""

    @pytest.mark.django_db
    def test_default_signup_form_valid(self):
        """Test DefaultSignUpForm with valid data."""
        data = {
            'username': 'testuser', 'email': 'test@example.com', 'first_name': 'Test',
            'last_name': 'User', 'phone_number': '1234567890', 'password1': 'testpass123',
            'password2': 'testpass123'
        }
        form = DefaultSignUpForm(data=data)
        assert form.is_valid()

    @pytest.mark.django_db
    def test_default_signup_form_invalid_phone(self):
        """Test DefaultSignUpForm with invalid phone_number."""
        data = {
            'username': 'testuser', 'email': 'test@example.com', 'first_name': 'Test',
            'last_name': 'User', 'phone_number': 'abc', 'password1': 'testpass123',
            'password2': 'testpass123'
        }
        form = DefaultSignUpForm(data=data)
        assert not form.is_valid()
        assert 'phone_number' in form.errors

    def test_pin_form_valid(self):
        """Test PinForm with valid PIN."""
        form = PinForm(data={'pin': '123456'})
        assert form.is_valid()

    def test_pin_form_invalid(self):
        """Test PinForm with invalid PIN."""
        form = PinForm(data={'pin': 'abc'})
        assert not form.is_valid()
        assert 'pin' in form.errors

    def test_invitation_form_invalid_role(self):
        """Test InvitationForm prevents 'etudiant' role."""
        form = InvitationForm(data={'role': 'etudiant', 'email': 'student@example.com'})
        assert not form.is_valid()
        assert 'role' in form.errors

    @pytest.mark.django_db
    def test_note_admin_form_valid(self, etudiant_user, academic_data):
        """Test NoteAdminForm with valid data."""
        annee, _, _, _, matiere, _ = academic_data
        data = {
            'etudiant': etudiant_user.etudiant_profile.id, 'matiere': matiere.id, 'annee': annee.id,
            'cc_note': 10.0, 'normal_note': 15.0, 'note_final': 12.5
        }
        form = NoteAdminForm(data=data)
        assert form.is_valid()

# ### View Tests

class TestViews:
    """Tests for view responses, redirects, and logic."""

    @pytest.mark.django_db
    def test_etudiant_signup_get(self, client):
        """Test GET request to etudiant_signup view."""
        response = client.get(reverse('roles:etudiant_signup'))
        assert response.status_code == 200
        assert 'roles/signup.html' in [t.name for t in response.templates]

    @pytest.mark.django_db
    def test_etudiant_signup_post_valid(self, client, mocker):
        """Test POST request to etudiant_signup with valid unique data."""
        mocker.patch('django.core.mail.send_mail')
        unique_suffix = timezone.now().timestamp()
        data = {
            'username': f'newuser_{unique_suffix}',
            'email': f'newuser_{unique_suffix}@example.com',
            'first_name': 'New',
            'last_name': 'User',
            'phone_number': '1234567890',
            'password1': 'testpass123',
            'password2': 'testpass123'
        }
        response = client.post(reverse('roles:etudiant_signup'), data)
        assert response.status_code == 302
        assert response.url == reverse('roles:signin')
        user = User.objects.get(username=data['username'])
        assert user.role == 'etudiant'
        assert not user.is_active
        assert Etudiant.objects.filter(user=user).exists()

    @pytest.mark.django_db
    def test_etudiant_signup_post_duplicate_username(self, client, etudiant_user, mocker):
        """Test POST request to etudiant_signup with duplicate username."""
        mocker.patch('django.core.mail.send_mail')
        data = {
            'username': 'etudiant',  # Duplicate username
            'email': 'newemail@example.com',
            'first_name': 'New',
            'last_name': 'User',
            'phone_number': '1234567890',
            'password1': 'testpass123',
            'password2': 'testpass123'
        }
        response = client.post(reverse('roles:etudiant_signup'), data)
        assert response.status_code == 200  # Stays on page due to form error
        assert 'username' in response.context['form'].errors  # Check for username validation error

    @pytest.mark.django_db
    def test_activate_account_valid(self, client, etudiant_user):
        """Test account activation with valid token."""
        etudiant_user.is_active = False
        etudiant_user.save()
        uid = urlsafe_base64_encode(force_bytes(etudiant_user.pk))
        token = default_token_generator.make_token(etudiant_user)
        response = client.get(reverse('roles:activate', kwargs={'uidb64': uid, 'token': token}))
        assert response.status_code == 302
        assert response.url == reverse('roles:signin')
        etudiant_user.refresh_from_db()
        assert etudiant_user.is_active

    @pytest.mark.django_db
    def test_signin_post_valid(self, client, etudiant_user):
        """Test successful login."""
        response = client.post(reverse('roles:signin'), {'username': 'etudiant', 'password': 'password'})
        assert response.status_code == 302
        assert response.url == '/etudiant/dashboard/'

    @pytest.mark.django_db
    def test_verify_invitation_valid_pin(self, client, invitation_admin):
        """Test verifying invitation with correct PIN."""
        # Ensure the PIN is set correctly in the fixture
        invitation_admin.set_pin('123456')
        invitation_admin.save()
        response = client.post(
            reverse('roles:verify_invitation', args=[invitation_admin.token]), {'pin': '123456'}
        )
        assert response.status_code == 302
        assert response.url == reverse('roles:invited_signup', args=[invitation_admin.token])

    @pytest.mark.django_db
    def test_verify_invitation_invalid_pin(self, client, invitation_admin):
        """Test verifying invitation with incorrect PIN."""
        # Ensure the PIN is set correctly in the fixture
        invitation_admin.set_pin('123456')
        invitation_admin.save()
        response = client.post(
            reverse('roles:verify_invitation', args=[invitation_admin.token]), {'pin': '999999'}
        )
        assert response.status_code == 200  # Stays on page due to error
        invitation_admin.refresh_from_db()
        assert invitation_admin.attempt_count == 1
        messages = [m.message for m in response.context['messages']]
        assert any('Incorrect PIN' in msg for msg in messages)

    @pytest.mark.django_db
    def test_verify_invitation_expired(self, client, invitation_admin):
        """Test verifying expired invitation."""
        invitation_admin.expires_at = timezone.now() - timedelta(days=1)
        invitation_admin.save()
        response = client.post(
            reverse('roles:verify_invitation', args=[invitation_admin.token]), {'pin': '123456'}
        )
        assert response.status_code == 302
        assert response.url == reverse('roles:signin')
        # Follow the redirect to check messages
        response = client.get(response.url)
        messages = [m.message for m in response.context['messages']]
        assert any('Invitation has expired.' in msg for msg in messages)

    @pytest.mark.django_db
    def test_invited_signup_valid(self, client, invitation_admin, mocker):
        """Test signup via invitation with valid data."""
        mocker.patch('django.core.mail.send_mail')
        unique_suffix = timezone.now().timestamp()
        data = {
            'username': f'inviteduser_{unique_suffix}',
            'email': invitation_admin.email,  # Must match invitation email
            'first_name': 'Invited',
            'last_name': 'User',
            'phone_number': '1234567890',
            'password1': 'testpass123',
            'password2': 'testpass123'
        }
        response = client.post(reverse('roles:invited_signup', args=[invitation_admin.token]), data)
        assert response.status_code == 302
        assert response.url == reverse('roles:signin')
        user = User.objects.get(username=data['username'])
        assert user.role == invitation_admin.role
        assert user.email == invitation_admin.email
        assert not user.is_active
        assert Enseignant.objects.filter(user=user).exists()  # Role-specific profile
        invitation_admin.refresh_from_db()
        assert invitation_admin.status == 'accepted'

    @pytest.mark.django_db
    def test_send_invitation_access(self, client, admin_user, etudiant_user):
        """Test access control for send_invitation view."""
        client.force_login(admin_user)
        response = client.get(reverse('roles:send_invitation'))
        assert response.status_code == 200
        client.force_login(etudiant_user)
        response = client.get(reverse('roles:send_invitation'))
        assert response.status_code == 302
        assert response.url == reverse('roles:signin')

    @pytest.mark.django_db
    def test_etudiant_dashboard_access(self, client, etudiant_user, admin_user):
        """Test role-based access to etudiant_dashboard."""
        client.force_login(etudiant_user)
        response = client.get(reverse('roles:etudiant_dashboard'))
        assert response.status_code == 200
        client.force_login(admin_user)
        response = client.get(reverse('roles:etudiant_dashboard'))
        assert response.status_code == 302
        assert response.url == reverse('roles:signin')

    @pytest.mark.django_db
    def test_resend_activation_valid(self, client, etudiant_user, mocker):
        """Test resending activation email for inactive user."""
        mocker.patch('django.core.mail.send_mail')
        etudiant_user.is_active = False
        etudiant_user.save()
        data = {'email': etudiant_user.email}
        response = client.post(reverse('roles:resend_activation'), data)
        assert response.status_code == 302
        assert response.url == reverse('roles:signin')