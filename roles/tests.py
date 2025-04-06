import pytest
from django.db import IntegrityError
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import timedelta
from roles.models import (
    User, Invitation, Annee, Filiere, Niveau, Semestre, Admin, Enseignant, Etudiant,
    Matiere, MatiereCommune, Note, AdminAnnee, AdminFiliere, AdminSemestre,
    EnseignantAnnee, EnseignantFiliere, EnseignantMatiere, EnseignantMatiereCommune,
    EnseignantNiveau, EnseignantSemestre, EtudiantAnnee, EtudiantSemestre,
    MatiereEtudiant, MatiereCommuneEtudiant
)

# User Model Tests
@pytest.mark.django_db
def test_user_creation():
    """Test that a user can be created and __str__ returns the expected string."""
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

@pytest.mark.django_db
def test_unique_email():
    """Test that the email field enforces uniqueness."""
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
    """Test that get_redirect_url returns the correct URL based on role."""
    roles_urls = {
        'etudiant': '/etudiant/dashboard/',
        'enseignant': '/enseignant/dashboard/',
        'admin': '/admin/panel/',
        'superadmin': '/superadmin/panel/'
    }
    for role, expected_url in roles_urls.items():
        user = User(role=role)
        assert user.get_redirect_url() == expected_url

# Invitation Model Tests
@pytest.mark.django_db
def test_invitation_creation():
    """Test that an invitation is created with correct attributes."""
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
        invitee_email='invitee@example.com',
        expires_at=timezone.now() + timedelta(minutes=1)
    )
    assert invitation.status == 'pending'
    assert not invitation.is_expired()

@pytest.mark.django_db
def test_invitation_expiration():
    """Test the is_expired method."""
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
        expires_at=timezone.now() - timedelta(minutes=1)  # Already expired
    )
    assert invitation.is_expired()

@pytest.mark.django_db
def test_save_validation_admin_role():
    """Test that admins can only invite other admins."""
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
    """Test that only admins and superadmins can send invitations."""
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

# Basic Model Tests (Annee, Filiere, Niveau, Semestre)
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

# Admin Profile Tests
@pytest.mark.django_db
def test_admin_creation():
    """Test that an admin profile is created with a one-to-one relationship."""
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
def test_admin_many_to_many_relationships():
    """Test many-to-many relationships with Annee, Filiere, and Semestre."""
    user = User.objects.create_user(
        username='admin',
        email='admin@example.com',
        password='pass',
        role='admin'
    )
    admin = Admin.objects.create(user=user)
    annee = Annee.objects.create(annee='2023-2024')
    filiere = Filiere.objects.create(nom_filiere='Informatique')
    semestre = Semestre.objects.create(nom_semestre='S1')
    AdminAnnee.objects.create(admin=admin, annee=annee)
    AdminFiliere.objects.create(admin=admin, filiere=filiere)
    AdminSemestre.objects.create(admin=admin, semestre=semestre)
    assert annee in admin.annees.all()
    assert filiere in admin.filieres.all()
    assert semestre in admin.semestres.all()

# Enseignant Profile Tests
@pytest.mark.django_db
def test_enseignant_creation():
    """Test that an enseignant profile is created."""
    user = User.objects.create_user(
        username='teacher',
        email='teacher@example.com',
        password='pass',
        role='enseignant'
    )
    enseignant = Enseignant.objects.create(user=user)
    assert enseignant.user == user

@pytest.mark.django_db
def test_enseignant_many_to_many_relationships():
    """Test many-to-many relationships with Annee, Filiere, Matiere, etc."""
    user = User.objects.create_user(
        username='teacher',
        email='teacher@example.com',
        password='pass',
        role='enseignant'
    )
    enseignant = Enseignant.objects.create(user=user)
    annee = Annee.objects.create(annee='2023-2024')
    filiere = Filiere.objects.create(nom_filiere='Informatique')
    niveau = Niveau.objects.create(nom_niveau='L1')
    semestre = Semestre.objects.create(nom_semestre='S1')
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
    EnseignantAnnee.objects.create(enseignant=enseignant, annee=annee)
    EnseignantFiliere.objects.create(enseignant=enseignant, filiere=filiere)
    EnseignantMatiere.objects.create(enseignant=enseignant, matiere=matiere)
    EnseignantMatiereCommune.objects.create(enseignant=enseignant, matiere_commune=matiere_commune)
    EnseignantNiveau.objects.create(enseignant=enseignant, niveau=niveau)
    EnseignantSemestre.objects.create(enseignant=enseignant, semestre=semestre)
    assert annee in enseignant.annees.all()
    assert filiere in enseignant.filieres.all()
    assert matiere in enseignant.matieres.all()
    assert matiere_commune in enseignant.matieres_communes.all()
    assert niveau in enseignant.niveaux.all()
    assert semestre in enseignant.semestres.all()

# Etudiant Profile Tests
@pytest.mark.django_db
def test_etudiant_creation():
    """Test that an etudiant profile is created with foreign keys."""
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

@pytest.mark.django_db
def test_etudiant_many_to_many_relationships():
    """Test many-to-many relationships with Annee, Semestre, Matiere, etc."""
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
    semestre = Semestre.objects.create(nom_semestre='S1')
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
    EtudiantAnnee.objects.create(etudiant=etudiant, annee=annee)
    EtudiantSemestre.objects.create(etudiant=etudiant, semestre=semestre)
    MatiereEtudiant.objects.create(etudiant=etudiant, matiere=matiere)
    MatiereCommuneEtudiant.objects.create(etudiant=etudiant, matiere_commune=matiere_commune)
    assert annee in etudiant.annees.all()
    assert semestre in etudiant.semestres.all()
    assert matiere in etudiant.matieres.all()
    assert matiere_commune in etudiant.matieres_communes.all()

# Matiere and MatiereCommune Tests
@pytest.mark.django_db
def test_matiere_creation():
    """Test that a matiere is created with unique course_code."""
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

@pytest.mark.django_db
def test_unique_course_code():
    """Test that course_code is unique in Matiere."""
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
    """Test that a matiere_commune is created with unique course_code."""
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

@pytest.mark.django_db
def test_unique_course_code_matiere_commune():
    """Test that course_code is unique in MatiereCommune."""
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

# Note Model Tests
@pytest.mark.django_db
def test_unique_together_constraint():
    """Test that the unique_together constraint is enforced in Note."""
    filiere = Filiere.objects.create(nom_filiere='Informatique')
    niveau = Niveau.objects.create(nom_niveau='L1')
    semestre = Semestre.objects.create(nom_semestre='S1')
    user = User.objects.create_user(
        username='student',
        email='student@example.com',
        password='testpass',
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

# Through Model Tests (Example for AdminAnnee)
@pytest.mark.django_db
def test_admin_annee_unique_together():
    """Test that AdminAnnee enforces unique_together."""
    user = User.objects.create_user(
        username='admin',
        email='admin@example.com',
        password='pass',
        role='admin'
    )
    admin = Admin.objects.create(user=user)
    annee = Annee.objects.create(annee='2023-2024')
    AdminAnnee.objects.create(admin=admin, annee=annee)
    with pytest.raises(IntegrityError):
        AdminAnnee.objects.create(admin=admin, annee=annee)