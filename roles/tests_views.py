import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.utils import timezone
from datetime import timedelta
import uuid
from .models import (
    User, Invitation, Annee, Filiere, Niveau, Semestre, Admin, Enseignant, Etudiant,
    Matiere, MatiereCommune, Note, EnseignantAnnee, EtudiantAnnee, MatiereEtudiant,
    MatiereCommuneEtudiant, ProfileEnseignant, ProfileEtudiant
)

User = get_user_model()

# Helper function to create a user
def create_user(username, email, role, password='testpass123', phone_number='1234567890'):
    return User.objects.create_user(
        username=username,
        email=email,
        password=password,
        role=role,
        phone_number=phone_number
    )

# Tests for User Model
@pytest.mark.django_db
class TestUserModel:
    def test_create_valid_user(self):
        user = create_user('testuser', 'test@example.com', 'etudiant')
        assert user.username == 'testuser'
        assert user.email == 'test@example.com'
        assert user.role == 'etudiant'
        assert user.phone_number == '1234567890'

    def test_email_must_be_unique(self):
        create_user('user1', 'unique@example.com', 'etudiant')
        with pytest.raises(IntegrityError):
            create_user('user2', 'unique@example.com', 'etudiant')

    def test_phone_number_only_digits(self):
        user = User(username='testphone', email='phone@example.com', phone_number='abc123', role='etudiant')
        with pytest.raises(ValidationError):
            user.full_clean()

    def test_phone_number_max_length(self):
        user = User(username='testmax', email='max@example.com', phone_number='1' * 16, role='etudiant')
        with pytest.raises(ValidationError):
            user.full_clean()

    def test_invalid_role_raises_error(self):
        user = User(username='invalidrole', email='invalid@example.com', role='invalid')
        with pytest.raises(ValidationError):
            user.full_clean()

    def test_get_redirect_url_by_role(self):
        user = create_user('adminuser', 'admin@example.com', 'admin')
        assert user.get_redirect_url() == '/admin/panel/'
        user.role = 'etudiant'
        assert user.get_redirect_url() == '/etudiant/dashboard/'

# Tests for Invitation Model
@pytest.mark.django_db
class TestInvitationModel:
    def test_create_valid_invitation(self):
        inviter = create_user('inviter', 'inviter@example.com', 'admin')
        invitation = Invitation.objects.create(
            role='enseignant',
            email='invited@example.com',
            inviter=inviter,
            expires_at=timezone.now() + timedelta(days=1)
        )
        assert invitation.role == 'enseignant'
        assert invitation.email == 'invited@example.com'
        assert invitation.inviter == inviter
        assert invitation.status == 'pending'

    def test_set_and_verify_pin(self):
        inviter = create_user('pinuser', 'pin@example.com', 'admin')
        invitation = Invitation.objects.create(
            role='enseignant',
            email='pin@example.com',
            inviter=inviter,
            expires_at=timezone.now() + timedelta(days=1)
        )
        invitation.set_pin('123456')
        invitation.save()
        assert invitation.check_pin('123456') is True
        assert invitation.check_pin('wrongpin') is False

    def test_invalid_pin_length(self):
        inviter = create_user('pinuser', 'pin@example.com', 'admin')
        invitation = Invitation.objects.create(
            role='enseignant',
            email='pin@example.com',
            inviter=inviter,
            expires_at=timezone.now() + timedelta(days=1)
        )
        with pytest.raises(ValidationError):
            invitation.set_pin('12345')  # Less than 6 digits

    def test_is_expired_logic(self):
        inviter = create_user('expireuser', 'expire@example.com', 'admin')
        invitation = Invitation.objects.create(
            role='enseignant',
            email='expire@example.com',
            inviter=inviter,
            expires_at=timezone.now() - timedelta(days=1)
        )
        assert invitation.is_expired() is True

    def test_inviter_role_restriction(self):
        inviter = create_user('studentinviter', 'student@example.com', 'etudiant')
        with pytest.raises(ValidationError):
            Invitation.objects.create(
                role='enseignant',
                email='test@example.com',
                inviter=inviter,
                expires_at=timezone.now() + timedelta(days=1)
            )

    def test_admin_cannot_invite_admin(self):
        inviter = create_user('admininviter', 'admin@example.com', 'admin')
        with pytest.raises(ValidationError):
            Invitation.objects.create(
                role='admin',
                email='test@example.com',
                inviter=inviter,
                expires_at=timezone.now() + timedelta(days=1)
            )

    def test_token_uniqueness(self):
        inviter = create_user('tokenuser', 'token@example.com', 'admin')
        token = uuid.uuid4()
        Invitation.objects.create(
            role='enseignant',
            email='token1@example.com',
            inviter=inviter,
            token=token,
            expires_at=timezone.now() + timedelta(days=1)
        )
        with pytest.raises(IntegrityError):
            Invitation.objects.create(
                role='enseignant',
                email='token2@example.com',
                inviter=inviter,
                token=token,
                expires_at=timezone.now() + timedelta(days=1)
            )

# Tests for Profile Models
@pytest.mark.django_db
class TestProfileModels:
    def test_create_etudiant_profile(self):
        user = create_user('student', 'student@example.com', 'etudiant')
        profile = Etudiant.objects.create(user=user, filiere='Science', niveau='L1')
        assert profile.user == user
        assert profile.filiere == 'Science'
        assert profile.niveau == 'L1'

    def test_etudiant_profile_one_to_one(self):
        user = create_user('student2', 'student2@example.com', 'etudiant')
        Etudiant.objects.create(user=user)
        with pytest.raises(IntegrityError):
            Etudiant.objects.create(user=user)

    def test_create_enseignant_profile(self):
        user = create_user('teacher', 'teacher@example.com', 'enseignant')
        profile = Enseignant.objects.create(user=user)
        assert profile.user == user

    def test_enseignant_profile_one_to_one(self):
        user = create_user('teacher2', 'teacher2@example.com', 'enseignant')
        Enseignant.objects.create(user=user)
        with pytest.raises(IntegrityError):
            Enseignant.objects.create(user=user)

    def test_create_admin_profile(self):
        user = create_user('adminuser', 'admin@example.com', 'admin')
        profile = Admin.objects.create(user=user)
        assert profile.user == user

    def test_admin_profile_one_to_one(self):
        user = create_user('admin2', 'admin2@example.com', 'admin')
        Admin.objects.create(user=user)
        with pytest.raises(IntegrityError):
            Admin.objects.create(user=user)

# Tests for Other Models
@pytest.mark.django_db
class TestOtherModels:
    def test_create_annee(self):
        annee = Annee.objects.create(annee='2023-2024')
        assert annee.annee == '2023-2024'

    def test_create_filiere(self):
        filiere = Filiere.objects.create(nom_filiere='Informatique')
        assert filiere.nom_filiere == 'Informatique'

    def test_create_niveau(self):
        niveau = Niveau.objects.create(nom_niveau='L1')
        assert niveau.nom_niveau == 'L1'

    def test_create_semestre(self):
        semestre = Semestre.objects.create(nom_semestre='S1')
        assert semestre.nom_semestre == 'S1'

    def test_create_matiere(self):
        filiere = Filiere.objects.create(nom_filiere='Informatique')
        semestre = Semestre.objects.create(nom_semestre='S1')
        niveau = Niveau.objects.create(nom_niveau='L1')
        matiere = Matiere.objects.create(
            nom_matiere='Algorithmique',
            course_code='ALG101',
            filiere=filiere,
            semestre=semestre,
            niveau=niveau
        )
        assert matiere.nom_matiere == 'Algorithmique'
        assert matiere.course_code == 'ALG101'

    def test_matiere_course_code_unique(self):
        Matiere.objects.create(nom_matiere='Math', course_code='MATH101')
        with pytest.raises(IntegrityError):
            Matiere.objects.create(nom_matiere='Physics', course_code='MATH101')

    def test_create_matiere_commune(self):
        filiere = Filiere.objects.create(nom_filiere='Informatique')
        semestre = Semestre.objects.create(nom_semestre='S1')
        niveau = Niveau.objects.create(nom_niveau='L1')
        matiere_commune = MatiereCommune.objects.create(
            nom_matiere_commune='Math',
            course_code='MATH101',
            filiere=filiere,
            semestre=semestre,
            niveau=niveau
        )
        assert matiere_commune.nom_matiere_commune == 'Math'
        assert matiere_commune.course_code == 'MATH101'

    def test_create_note(self):
        user = create_user('notestudent', 'notestudent@example.com', 'etudiant')
        etudiant = Etudiant.objects.create(user=user)
        matiere = Matiere.objects.create(nom_matiere='Math', course_code='MATH101')
        annee = Annee.objects.create(annee='2023-2024')
        note = Note.objects.create(
            etudiant=etudiant,
            matiere=matiere,
            cc_note=15.0,
            normal_note=16.0,
            note_final=15.5,
            annee=annee
        )
        assert note.etudiant == etudiant
        assert note.matiere == matiere
        assert note.cc_note == 15.0

    def test_note_unique_together_constraint(self):
        # Create necessary objects
        user = create_user('constraintuser', 'constraint@example.com', 'etudiant')
        etudiant = Etudiant.objects.create(user=user)
        matiere = Matiere.objects.create(nom_matiere='Math', course_code='MATH101')
        matiere_commune = MatiereCommune.objects.create(nom_matiere_commune='CommonMath', course_code='CMATH101')
        annee = Annee.objects.create(annee='2023-2024')

        # Create the first Note
        Note.objects.create(
            etudiant=etudiant,
            matiere=matiere,
            matiere_commune=matiere_commune,
            cc_note=15.0,
            normal_note=16.0,
            note_final=15.5,
            annee=annee
        )

        # Attempt to create a second Note with the same unique_together fields
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

    def test_create_profile_enseignant(self):
        user = create_user('teacher', 'teacher@example.com', 'enseignant')
        enseignant = Enseignant.objects.create(user=user)
        annee = Annee.objects.create(annee='2023-2024')
        matiere = Matiere.objects.create(nom_matiere='Math', course_code='MATH101')
        profile = ProfileEnseignant.objects.create(
            enseignant=enseignant,
            annee=annee,
            matiere=matiere,
            validated=True
        )
        assert profile.enseignant == enseignant
        assert profile.validated is True

    def test_create_profile_etudiant(self):
        user = create_user('student', 'student@example.com', 'etudiant')
        etudiant = Etudiant.objects.create(user=user)
        filiere = Filiere.objects.create(nom_filiere='Informatique')
        matiere = Matiere.objects.create(nom_matiere='Math', course_code='MATH101')
        semestre = Semestre.objects.create(nom_semestre='S1')
        annee = Annee.objects.create(annee='2023-2024')
        niveau = Niveau.objects.create(nom_niveau='L1')
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

    def test_profile_etudiant_unique_together(self):
        user = create_user('constraintstudent', 'constraintstudent@example.com', 'etudiant')
        etudiant = Etudiant.objects.create(user=user)
        annee = Annee.objects.create(annee='2023-2024')
        filiere = Filiere.objects.create(nom_filiere='Informatique')
        matiere = Matiere.objects.create(nom_matiere='Math', course_code='MATH101')
        semestre = Semestre.objects.create(nom_semestre='S1')
        niveau = Niveau.objects.create(nom_niveau='L1')
        ProfileEtudiant.objects.create(
            etudiant=etudiant,
            filiere=filiere,
            matiere=matiere,
            semestre=semestre,
            annee=annee,
            niveau=niveau
        )
        with pytest.raises(IntegrityError):
            ProfileEtudiant.objects.create(
                etudiant=etudiant,
                filiere=filiere,
                matiere=matiere,
                semestre=semestre,
                annee=annee,
                niveau=niveau
            )

    def test_etudiant_annee_unique_together(self):
        user = create_user('yearstudent', 'yearstudent@example.com', 'etudiant')
        etudiant = Etudiant.objects.create(user=user)
        annee = Annee.objects.create(annee='2023-2024')
        EtudiantAnnee.objects.create(etudiant=etudiant, annee=annee)
        with pytest.raises(IntegrityError):
            EtudiantAnnee.objects.create(etudiant=etudiant, annee=annee)