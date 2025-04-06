import pytest
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.utils import timezone
from datetime import timedelta
from .models import (
    User, Invitation, Annee, Filiere, Niveau, Semestre,
    Admin, Enseignant, Etudiant, Matiere, MatiereCommune,
    Note, EnseignantAnnee, EtudiantAnnee, MatiereEtudiant,
    MatiereCommuneEtudiant, ProfileEnseignant, ProfileEtudiant
)

# --- User Model Tests ---
@pytest.mark.django_db
def test_user_creation():
    """Test basic user creation and __str__ method."""
    user = User.objects.create_user(
        username='testuser',
        email='test@example.com',
        password='testpass',
        role='etudiant',
        first_name='John',
        last_name='Doe',
        phone_number='1234567890'
    )
    assert str(user) == 'John Doe (etudiant)'
    assert user.email == 'test@example.com'
    assert user.phone_number == '1234567890'

@pytest.mark.django_db
def test_unique_email():
    """Test email uniqueness constraint."""
    User.objects.create_user(
        username='user1',
        email='unique@example.com',
        password='pass',
        role='admin'
    )
    with pytest.raises(IntegrityError):
        User.objects.create_user(
            username='user2',
            email='unique@example.com',
            password='pass',
            role='admin'
        )

def test_get_redirect_url():
    """Test get_redirect_url method for each role."""
    roles_urls = {
        'etudiant': '/etudiant/dashboard/',
        'enseignant': '/enseignant/dashboard/',
        'admin': '/admin/panel/',
        'superadmin': '/superadmin/panel/'
    }
    for role, expected_url in roles_urls.items():
        user = User(role=role)
        assert user.get_redirect_url() == expected_url

# --- Invitation Model Tests ---
@pytest.mark.django_db
def test_invitation_creation():
    """Test invitation creation with default expires_at."""
    admin = User.objects.create_user(
        username='admin',
        email='admin@example.com',
        password='adminpass',
        role='admin'
    )
    invitation = Invitation.objects.create(
        role='admin',
        pin='123456',
        inviter=admin,
        invitee_email='invitee@example.com'
    )
    assert invitation.status == 'pending'
    assert invitation.expires_at > timezone.now()
    assert not invitation.is_expired()
    assert str(invitation) == f"Invitation for admin to invitee@example.com by {admin}"

@pytest.mark.django_db
def test_invitation_expiration():
    """Test is_expired method with an expired invitation."""
    admin = User.objects.create_user(
        username='admin',
        email='admin@example.com',
        password='adminpass',
        role='admin'
    )
    invitation = Invitation.objects.create(
        role='admin',
        pin='654321',
        inviter=admin,
        invitee_email='invitee@example.com',
        expires_at=timezone.now() - timedelta(minutes=1)
    )
    assert invitation.is_expired()

@pytest.mark.django_db
def test_save_validation_admin_role():
    """Test validation: admins can only invite admins."""
    admin = User.objects.create_user(
        username='admin',
        email='admin@example.com',
        password='adminpass',
        role='admin'
    )
    with pytest.raises(ValidationError):
        Invitation.objects.create(
            role='etudiant',
            pin='111111',
            inviter=admin,
            invitee_email='student@example.com'
        )

@pytest.mark.django_db
def test_save_validation_non_admin():
    """Test validation: only admins/superadmins can send invitations."""
    non_admin = User.objects.create_user(
        username='teacher',
        email='teacher@example.com',
        password='pass',
        role='enseignant'
    )
    with pytest.raises(ValidationError):
        Invitation.objects.create(
            role='enseignant',
            pin='222222',
            inviter=non_admin,
            invitee_email='newteacher@example.com'
        )

# --- Simple Model Tests (Annee, Filiere, Niveau, Semestre) ---
@pytest.mark.django_db
def test_annee_creation():
    """Test Annee model creation."""
    annee = Annee.objects.create(annee='2023-2024')
    assert Annee.objects.count() == 1
    assert annee.annee == '2023-2024'

@pytest.mark.django_db
def test_filiere_creation():
    """Test Filiere model creation."""
    filiere = Filiere.objects.create(nom_filiere='Informatique')
    assert Filiere.objects.count() == 1
    assert filiere.nom_filiere == 'Informatique'

@pytest.mark.django_db
def test_niveau_creation():
    """Test Niveau model creation."""
    niveau = Niveau.objects.create(nom_niveau='L1')
    assert Niveau.objects.count() == 1
    assert niveau.nom_niveau == 'L1'

@pytest.mark.django_db
def test_semestre_creation():
    """Test Semestre model creation."""
    semestre = Semestre.objects.create(nom_semestre='S1')
    assert Semestre.objects.count() == 1
    assert semestre.nom_semestre == 'S1'

# --- Profile Model Tests (Admin, Enseignant, Etudiant) ---
@pytest.mark.django_db
def test_admin_creation():
    """Test Admin profile creation with auto_now_add."""
    user = User.objects.create_user(
        username='admin',
        email='admin@example.com',
        password='pass',
        role='admin'
    )
    admin = Admin.objects.create(user=user)
    assert admin.user == user
    assert admin.date_creation is not None

@pytest.mark.django_db
def test_enseignant_creation():
    """Test Enseignant profile creation."""
    user = User.objects.create_user(
        username='teacher',
        email='teacher@example.com',
        password='pass',
        role='enseignant'
    )
    enseignant = Enseignant.objects.create(user=user)
    assert enseignant.user == user
    assert enseignant.date_creation is not None

@pytest.mark.django_db
def test_etudiant_creation():
    """Test Etudiant profile creation with relationships."""
    user = User.objects.create_user(
        username='student',
        email='student@example.com',
        password='pass',
        role='etudiant'
    )
    filiere = Filiere.objects.create(nom_filiere='Informatique')
    niveau = Niveau.objects.create(nom_niveau='L1')
    etudiant = Etudiant.objects.create(user=user, filiere=filiere, niveau=niveau)
    assert etudiant.user == user
    assert etudiant.filiere == filiere
    assert etudiant.niveau == niveau
    assert etudiant.date_creation is not None

# --- Matiere and MatiereCommune Tests ---
@pytest.mark.django_db
def test_matiere_creation():
    """Test Matiere creation."""
    filiere = Filiere.objects.create(nom_filiere='Informatique')
    semestre = Semestre.objects.create(nom_semestre='S1')
    niveau = Niveau.objects.create(nom_niveau='L1')
    matiere = Matiere.objects.create(
        nom_matiere='Math',
        course_code='MATH101',
        filiere=filiere,
        semestre=semestre,
        niveau=niveau
    )
    assert matiere.nom_matiere == 'Math'
    assert matiere.course_code == 'MATH101'

@pytest.mark.django_db
def test_unique_course_code_matiere():
    """Test unique course_code constraint for Matiere."""
    filiere = Filiere.objects.create(nom_filiere='Informatique')
    semestre = Semestre.objects.create(nom_semestre='S1')
    niveau = Niveau.objects.create(nom_niveau='L1')
    Matiere.objects.create(
        nom_matiere='Math',
        course_code='MATH101',
        filiere=filiere,
        semestre=semestre,
        niveau=niveau
    )
    with pytest.raises(IntegrityError):
        Matiere.objects.create(
            nom_matiere='Physics',
            course_code='MATH101',
            filiere=filiere,
            semestre=semestre,
            niveau=niveau
        )

@pytest.mark.django_db
def test_matiere_commune_creation():
    """Test MatiereCommune creation."""
    filiere = Filiere.objects.create(nom_filiere='Informatique')
    semestre = Semestre.objects.create(nom_semestre='S1')
    niveau = Niveau.objects.create(nom_niveau='L1')
    matiere_commune = MatiereCommune.objects.create(
        nom_matiere_commune='Physics',
        course_code='PHY101',
        filiere=filiere,
        semestre=semestre,
        niveau=niveau
    )
    assert matiere_commune.nom_matiere_commune == 'Physics'
    assert matiere_commune.course_code == 'PHY101'

@pytest.mark.django_db
def test_unique_course_code_matiere_commune():
    """Test unique course_code constraint for MatiereCommune."""
    filiere = Filiere.objects.create(nom_filiere='Informatique')
    semestre = Semestre.objects.create(nom_semestre='S1')
    niveau = Niveau.objects.create(nom_niveau='L1')
    MatiereCommune.objects.create(
        nom_matiere_commune='Physics',
        course_code='PHY101',
        filiere=filiere,
        semestre=semestre,
        niveau=niveau
    )
    with pytest.raises(IntegrityError):
        MatiereCommune.objects.create(
            nom_matiere_commune='Chemistry',
            course_code='PHY101',
            filiere=filiere,
            semestre=semestre,
            niveau=niveau
        )

# --- Note Model Tests ---
@pytest.mark.django_db
def test_unique_together_note():
    """Test unique_together constraint for Note."""
    filiere = Filiere.objects.create(nom_filiere='Informatique')
    niveau = Niveau.objects.create(nom_niveau='L1')
    semestre = Semestre.objects.create(nom_semestre='S1')
    user = User.objects.create_user(
        username='student',
        email='student@example.com',
        password='pass',
        role='etudiant'
    )
    etudiant = Etudiant.objects.create(user=user, filiere=filiere, niveau=niveau)
    matiere = Matiere.objects.create(
        nom_matiere='Math',
        course_code='MATH101',
        filiere=filiere,
        semestre=semestre,
        niveau=niveau
    )
    matiere_commune = MatiereCommune.objects.create(
        nom_matiere_commune='Physics',
        course_code='PHY101',
        filiere=filiere,
        semestre=semestre,
        niveau=niveau
    )
    annee = Annee.objects.create(annee='2023-2024')
    Note.objects.create(
        etudiant=etudiant,
        matiere=matiere,
        matiere_commune=matiere_commune,
        cc_note=15.0,
        normal_note=16.0,
        note_final=15.5,
        annee=annee
    )
    with pytest.raises(IntegrityError):
        Note.objects.create(
            etudiant=etudiant,
            matiere=matiere,
            matiere_commune=matiere_commune,
            cc_note=14.0,
            normal_note=15.0,
            note_final=14.5,
            annee=annee
        )

# --- Through Model Tests ---
@pytest.mark.django_db
def test_enseignant_annee_unique_together():
    """Test unique_together constraint for EnseignantAnnee."""
    user = User.objects.create_user(
        username='teacher',
        email='teacher@example.com',
        password='pass',
        role='enseignant'
    )
    enseignant = Enseignant.objects.create(user=user)
    annee = Annee.objects.create(annee='2023-2024')
    EnseignantAnnee.objects.create(enseignant=enseignant, annee=annee)
    with pytest.raises(IntegrityError):
        EnseignantAnnee.objects.create(enseignant=enseignant, annee=annee)

@pytest.mark.django_db
def test_etudiant_annee_unique_together():
    """Test unique_together constraint for EtudiantAnnee."""
    user = User.objects.create_user(
        username='student',
        email='student@example.com',
        password='pass',
        role='etudiant'
    )
    filiere = Filiere.objects.create(nom_filiere='Informatique')
    niveau = Niveau.objects.create(nom_niveau='L1')
    etudiant = Etudiant.objects.create(user=user, filiere=filiere, niveau=niveau)
    annee = Annee.objects.create(annee='2023-2024')
    EtudiantAnnee.objects.create(etudiant=etudiant, annee=annee)
    with pytest.raises(IntegrityError):
        EtudiantAnnee.objects.create(etudiant=etudiant, annee=annee)

@pytest.mark.django_db
def test_matiere_etudiant_unique_together():
    """Test unique_together constraint for MatiereEtudiant."""
    user = User.objects.create_user(
        username='student',
        email='student@example.com',
        password='pass',
        role='etudiant'
    )
    filiere = Filiere.objects.create(nom_filiere='Informatique')
    niveau = Niveau.objects.create(nom_niveau='L1')
    semestre = Semestre.objects.create(nom_semestre='S1')
    etudiant = Etudiant.objects.create(user=user, filiere=filiere, niveau=niveau)
    matiere = Matiere.objects.create(
        nom_matiere='Math',
        course_code='MATH101',
        filiere=filiere,
        semestre=semestre,
        niveau=niveau
    )
    annee = Annee.objects.create(annee='2023-2024')
    MatiereEtudiant.objects.create(etudiant=etudiant, matiere=matiere, annee=annee)
    with pytest.raises(IntegrityError):
        MatiereEtudiant.objects.create(etudiant=etudiant, matiere=matiere, annee=annee)

@pytest.mark.django_db
def test_matiere_commune_etudiant_unique_together():
    """Test unique_together constraint for MatiereCommuneEtudiant."""
    user = User.objects.create_user(
        username='student',
        email='student@example.com',
        password='pass',
        role='etudiant'
    )
    filiere = Filiere.objects.create(nom_filiere='Informatique')
    niveau = Niveau.objects.create(nom_niveau='L1')
    semestre = Semestre.objects.create(nom_semestre='S1')
    etudiant = Etudiant.objects.create(user=user, filiere=filiere, niveau=niveau)
    matiere_commune = MatiereCommune.objects.create(
        nom_matiere_commune='Physics',
        course_code='PHY101',
        filiere=filiere,
        semestre=semestre,
        niveau=niveau
    )
    annee = Annee.objects.create(annee='2023-2024')
    MatiereCommuneEtudiant.objects.create(etudiant=etudiant, matiere_commune=matiere_commune, annee=annee)
    with pytest.raises(IntegrityError):
        MatiereCommuneEtudiant.objects.create(etudiant=etudiant, matiere_commune=matiere_commune, annee=annee)

# --- New Model Tests (ProfileEnseignant, ProfileEtudiant) ---
@pytest.mark.django_db
def test_profile_enseignant_creation():
    """Test ProfileEnseignant creation with defaults."""
    user = User.objects.create_user(
        username='teacher',
        email='teacher@example.com',
        password='pass',
        role='enseignant'
    )
    enseignant = Enseignant.objects.create(user=user)
    annee = Annee.objects.create(annee='2023-2024')
    profile = ProfileEnseignant.objects.create(enseignant=enseignant, annee=annee)
    assert profile.enseignant == enseignant
    assert profile.annee == annee
    assert profile.validated is False
    assert profile.new_entry is True
    assert profile.date_creation is not None
    assert profile.matiere is None
    assert profile.matiere_commune is None

@pytest.mark.django_db
def test_profile_etudiant_creation():
    """Test ProfileEtudiant creation with relationships."""
    user = User.objects.create_user(
        username='student',
        email='student@example.com',
        password='pass',
        role='etudiant'
    )
    filiere = Filiere.objects.create(nom_filiere='Informatique')
    niveau = Niveau.objects.create(nom_niveau='L1')
    semestre = Semestre.objects.create(nom_semestre='S1')
    etudiant = Etudiant.objects.create(user=user, filiere=filiere, niveau=niveau)
    matiere = Matiere.objects.create(
        nom_matiere='Math',
        course_code='MATH101',
        filiere=filiere,
        semestre=semestre,
        niveau=niveau
    )
    annee = Annee.objects.create(annee='2023-2024')
    profile = ProfileEtudiant.objects.create(
        etudiant=etudiant,
        filiere=filiere,
        matiere=matiere,
        semestre=semestre,
        annee=annee,
        niveau=niveau
    )
    assert profile.etudiant == etudiant
    assert profile.filiere == filiere
    assert profile.matiere == matiere
    assert profile.semestre == semestre
    assert profile.annee == annee
    assert profile.niveau == niveau
    assert profile.matiere_commune is None