from django.test import TestCase
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

class UserModelTest(TestCase):
    def test_role_choices_valid(self):
        user = User(username='testuser', email='test@example.com', role='etudiant')
        user.set_password('password123')  # Set password to satisfy blank=False
        user.full_clean()  # Should not raise

    def test_role_choices_invalid(self):
        user = User(username='testuser', email='test@example.com', role='invalid_role')
        user.set_password('password123')
        with self.assertRaises(ValidationError):
            user.full_clean()

    def test_phone_number_validation_valid(self):
        user = User(username='testuser', email='test@example.com', role='etudiant', phone_number='1234567890')
        user.set_password('password123')  # Set password to satisfy blank=False
        user.full_clean()  # Should not raise

    def test_phone_number_validation_invalid(self):
        user = User(username='testuser', email='test@example.com', role='etudiant', phone_number='abc123')
        user.set_password('password123')
        with self.assertRaises(ValidationError):
            user.full_clean()

    def test_phone_number_max_length(self):
        user = User(username='testuser', email='test@example.com', role='etudiant', phone_number='1234567890123456')
        user.set_password('password123')
        with self.assertRaises(ValidationError):
            user.full_clean()

    def test_email_unique(self):
        User.objects.create(username='user1', email='duplicate@example.com', role='etudiant', password='password123')
        user2 = User(username='user2', email='duplicate@example.com', role='enseignant')
        user2.set_password('password123')
        with self.assertRaises(IntegrityError):
            user2.save()

    def test_str_method(self):
        user = User(first_name='John', last_name='Doe', role='etudiant')
        user.set_password('password123')
        self.assertEqual(str(user), 'John Doe (etudiant)')

    def test_get_redirect_url(self):
        user = User(role='etudiant')
        user.set_password('password123')
        self.assertEqual(user.get_redirect_url(), '/etudiant/dashboard/')
        user.role = 'enseignant'
        self.assertEqual(user.get_redirect_url(), '/enseignant/dashboard/')
        user.role = 'admin'
        self.assertEqual(user.get_redirect_url(), '/admin/panel/')
        user.role = 'superadmin'
        self.assertEqual(user.get_redirect_url(), '/superadmin/panel/')
        user.role = 'invalid'
        self.assertEqual(user.get_redirect_url(), '/signin/')

    def test_clean_method(self):
        user = User(username='testuser', email='test@example.com', role='etudiant', phone_number='abc123')
        user.set_password('password123')
        with self.assertRaises(ValidationError):
            user.clean()

class InvitationModelTest(TestCase):
    def setUp(self):
        self.superadmin = User.objects.create(username='superadmin', email='superadmin@example.com', role='superadmin', password='password123')
        self.admin = User.objects.create(username='admin', email='admin@example.com', role='admin', password='password123')
        self.enseignant = User.objects.create(username='enseignant', email='enseignant@example.com', role='enseignant', password='password123')

    def test_role_choices(self):
        invitation = Invitation(role='invalid_role', email='test@example.com', inviter=self.admin)
        invitation.set_pin('123456')  # Set PIN
        invitation.expires_at = timezone.now() + timedelta(days=1)  # Set expires_at
        with self.assertRaises(ValidationError):
            invitation.full_clean()
        invitation.role = 'enseignant'
        invitation.full_clean()  # Should not raise

    def test_status_choices(self):
        invitation = Invitation(role='enseignant', email='test@example.com', inviter=self.admin, status='invalid_status')
        invitation.set_pin('123456')  # Set PIN
        invitation.expires_at = timezone.now() + timedelta(days=1)  # Set expires_at
        with self.assertRaises(ValidationError):
            invitation.full_clean()
        invitation.status = 'pending'
        invitation.full_clean()  # Should not raise

    def test_token_unique(self):
        token = uuid.uuid4()
        Invitation.objects.create(role='enseignant', email='test1@example.com', inviter=self.admin, token=token, pin='hashedpin', expires_at=timezone.now())
        invitation2 = Invitation(role='enseignant', email='test2@example.com', inviter=self.admin, token=token, pin='hashedpin', expires_at=timezone.now())
        with self.assertRaises(IntegrityError):
            invitation2.save()

    def test_set_pin_valid(self):
        invitation = Invitation(role='enseignant', email='test@example.com', inviter=self.admin)
        invitation.set_pin('123456')
        self.assertTrue(invitation.check_pin('123456'))

    def test_set_pin_invalid_length(self):
        invitation = Invitation(role='enseignant', email='test@example.com', inviter=self.admin)
        with self.assertRaises(ValidationError):
            invitation.set_pin('12345')  # Too short
        with self.assertRaises(ValidationError):
            invitation.set_pin('1234567')  # Too long

    def test_set_pin_invalid_type(self):
        invitation = Invitation(role='enseignant', email='test@example.com', inviter=self.admin)
        with self.assertRaises(ValidationError):
            invitation.set_pin('abc123')  # Non-digits

    def test_check_pin(self):
        invitation = Invitation(role='enseignant', email='test@example.com', inviter=self.admin)
        invitation.set_pin('123456')
        self.assertTrue(invitation.check_pin('123456'))
        self.assertFalse(invitation.check_pin('654321'))

    def test_is_expired(self):
        past_time = timezone.now() - timedelta(days=1)
        future_time = timezone.now() + timedelta(days=1)
        invitation_past = Invitation(role='enseignant', email='past@example.com', inviter=self.admin, expires_at=past_time, pin='hashedpin')
        invitation_future = Invitation(role='enseignant', email='future@example.com', inviter=self.admin, expires_at=future_time, pin='hashedpin')
        self.assertTrue(invitation_past.is_expired())
        self.assertFalse(invitation_future.is_expired())

    def test_save_superadmin_invite(self):
        invitation = Invitation(role='admin', email='newadmin@example.com', inviter=self.superadmin)
        invitation.set_pin('123456')
        invitation.save()  # Should not raise

    def test_save_admin_invite_enseignant(self):
        invitation = Invitation(role='enseignant', email='newenseignant@example.com', inviter=self.admin)
        invitation.set_pin('123456')
        invitation.save()  # Should not raise

    def test_save_admin_invite_restricted(self):
        invitation = Invitation(role='admin', email='newadmin@example.com', inviter=self.admin)
        invitation.set_pin('123456')
        with self.assertRaises(ValidationError):
            invitation.save()

    def test_save_non_inviter_role(self):
        invitation = Invitation(role='enseignant', email='test@example.com', inviter=self.enseignant)
        invitation.set_pin('123456')
        with self.assertRaises(ValidationError):
            invitation.save()

    def test_save_etudiant_forbidden(self):
        invitation = Invitation(role='etudiant', email='newetudiant@example.com', inviter=self.superadmin)
        invitation.set_pin('123456')
        with self.assertRaises(ValidationError):
            invitation.save()

    def test_expires_at_auto_set(self):
        invitation = Invitation(role='enseignant', email='test@example.com', inviter=self.admin)
        invitation.set_pin('123456')
        invitation.save()
        self.assertAlmostEqual(invitation.expires_at.timestamp(), (timezone.now() + timedelta(hours=24)).timestamp(), delta=60)

    def test_str_method(self):
        invitation = Invitation(role='enseignant', email='test@example.com', inviter=self.admin)
        self.assertEqual(str(invitation), f"Invitation for enseignant to test@example.com by {self.admin}")

class AnneeModelTest(TestCase):
    def test_annee_max_length(self):
        annee = Annee(annee='2023-2024')
        annee.full_clean()  # Should not raise
        annee.annee = '2023-2024-EXTRA'
        with self.assertRaises(ValidationError):
            annee.full_clean()

    def test_annee_null(self):
        annee = Annee(annee=None)
        annee.full_clean()  # Should not raise

class FiliereModelTest(TestCase):
    def test_nom_filiere_max_length(self):
        filiere = Filiere(nom_filiere='Science')
        filiere.full_clean()  # Should not raise
        filiere.nom_filiere = 'A' * 51
        with self.assertRaises(ValidationError):
            filiere.full_clean()

class NiveauModelTest(TestCase):
    def test_nom_niveau_max_length(self):
        niveau = Niveau(nom_niveau='L1')
        niveau.full_clean()  # Should not raise
        niveau.nom_niveau = 'A' * 51
        with self.assertRaises(ValidationError):
            niveau.full_clean()

class SemestreModelTest(TestCase):
    def test_nom_semestre_max_length(self):
        semestre = Semestre(nom_semestre='S1')
        semestre.full_clean()  # Should not raise
        semestre.nom_semestre = 'A' * 51
        with self.assertRaises(ValidationError):
            semestre.full_clean()

class AdminModelTest(TestCase):
    def test_one_to_one_user(self):
        user = User.objects.create(username='admin1', email='admin1@example.com', role='admin', password='password123')
        admin = Admin.objects.create(user=user)
        self.assertEqual(str(admin), f"Admin Profile for {user}")
        with self.assertRaises(IntegrityError):
            Admin.objects.create(user=user)

    def test_date_creation_auto(self):
        user = User.objects.create(username='admin1', email='admin1@example.com', role='admin', password='password123')
        admin = Admin.objects.create(user=user)
        self.assertIsNotNone(admin.date_creation)

class EnseignantModelTest(TestCase):
    def test_one_to_one_user(self):
        user = User.objects.create(username='enseignant1', email='enseignant1@example.com', role='enseignant', password='password123')
        enseignant = Enseignant.objects.create(user=user)
        self.assertEqual(str(enseignant), f"Enseignant Profile for {user}")
        with self.assertRaises(IntegrityError):
            Enseignant.objects.create(user=user)

class EtudiantModelTest(TestCase):
    def test_one_to_one_user(self):
        user = User.objects.create(username='etudiant1', email='etudiant1@example.com', role='etudiant', password='password123')
        etudiant = Etudiant.objects.create(user=user)
        self.assertEqual(str(etudiant), f"Etudiant Profile for {user}")
        with self.assertRaises(IntegrityError):
            Etudiant.objects.create(user=user)

    def test_filiere_null_blank(self):
        user = User.objects.create(username='etudiant1', email='etudiant1@example.com', role='etudiant', password='password123')
        etudiant = Etudiant.objects.create(user=user, filiere=None)
        etudiant.full_clean()  # Should not raise

    def test_filiere_max_length(self):
        user = User.objects.create(username='etudiant1', email='etudiant1@example.com', role='etudiant', password='password123')
        etudiant = Etudiant(user=user, filiere='A' * 100)
        etudiant.full_clean()  # Should not raise
        etudiant.filiere = 'A' * 101
        with self.assertRaises(ValidationError):
            etudiant.full_clean()

class MatiereModelTest(TestCase):
    def setUp(self):
        self.filiere = Filiere.objects.create(nom_filiere='Science')
        self.semestre = Semestre.objects.create(nom_semestre='S1')
        self.niveau = Niveau.objects.create(nom_niveau='L1')

    def test_course_code_unique(self):
        Matiere.objects.create(nom_matiere='Math', course_code='M101', filiere=self.filiere, semestre=self.semestre, niveau=self.niveau)
        with self.assertRaises(IntegrityError):
            Matiere.objects.create(nom_matiere='Physics', course_code='M101', filiere=self.filiere, semestre=self.semestre, niveau=self.niveau)

    def test_nom_matiere_max_length(self):
        matiere = Matiere(nom_matiere='A' * 100, course_code='M101', filiere=self.filiere, semestre=self.semestre, niveau=self.niveau)
        matiere.full_clean()  # Should not raise
        matiere.nom_matiere = 'A' * 101
        with self.assertRaises(ValidationError):
            matiere.full_clean()

class MatiereCommuneModelTest(TestCase):
    def setUp(self):
        self.filiere = Filiere.objects.create(nom_filiere='Science')
        self.semestre = Semestre.objects.create(nom_semestre='S1')
        self.niveau = Niveau.objects.create(nom_niveau='L1')

    def test_course_code_unique(self):
        MatiereCommune.objects.create(nom_matiere_commune='Common Math', course_code='CM101', filiere=self.filiere, semestre=self.semestre, niveau=self.niveau)
        with self.assertRaises(IntegrityError):
            MatiereCommune.objects.create(nom_matiere_commune='Common Physics', course_code='CM101', filiere=self.filiere, semestre=self.semestre, niveau=self.niveau)

    def test_nom_matiere_commune_max_length(self):
        matiere = MatiereCommune(nom_matiere_commune='A' * 100, course_code='CM101', filiere=self.filiere, semestre=self.semestre, niveau=self.niveau)
        matiere.full_clean()  # Should not raise
        matiere.nom_matiere_commune = 'A' * 101
        with self.assertRaises(ValidationError):
            matiere.full_clean()

class NoteModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create(username='etudiant1', email='etudiant1@example.com', role='etudiant', password='password123')
        self.etudiant = Etudiant.objects.create(user=self.user)
        self.filiere = Filiere.objects.create(nom_filiere='Science')
        self.semestre = Semestre.objects.create(nom_semestre='S1')
        self.niveau = Niveau.objects.create(nom_niveau='L1')
        self.matiere = Matiere.objects.create(nom_matiere='Math', course_code='M101', filiere=self.filiere, semestre=self.semestre, niveau=self.niveau)
        self.matiere_commune = MatiereCommune.objects.create(nom_matiere_commune='Common Math', course_code='CM101', filiere=self.filiere, semestre=self.semestre, niveau=self.niveau)
        self.annee = Annee.objects.create(annee='2023-2024')

    def test_unique_together(self):
        Note.objects.create(etudiant=self.etudiant, matiere=self.matiere, matiere_commune=self.matiere_commune, annee=self.annee, cc_note=10.0, normal_note=15.0, note_final=12.5)
        with self.assertRaises(IntegrityError):
            Note.objects.create(etudiant=self.etudiant, matiere=self.matiere, matiere_commune=self.matiere_commune, annee=self.annee, cc_note=12.0, normal_note=16.0, note_final=14.0)

    def test_null_matiere(self):
        note = Note(etudiant=self.etudiant, matiere=None, matiere_commune=self.matiere_commune, annee=self.annee, cc_note=10.0, normal_note=15.0, note_final=12.5)
        note.full_clean()  # Should not raise

class EnseignantAnneeModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create(username='enseignant1', email='enseignant1@example.com', role='enseignant', password='password123')
        self.enseignant = Enseignant.objects.create(user=self.user)
        self.annee = Annee.objects.create(annee='2023-2024')

    def test_unique_together(self):
        EnseignantAnnee.objects.create(enseignant=self.enseignant, annee=self.annee)
        with self.assertRaises(IntegrityError):
            EnseignantAnnee.objects.create(enseignant=self.enseignant, annee=self.annee)

class EtudiantAnneeModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create(username='etudiant1', email='etudiant1@example.com', role='etudiant', password='password123')
        self.etudiant = Etudiant.objects.create(user=self.user)
        self.annee = Annee.objects.create(annee='2023-2024')

    def test_unique_together(self):
        EtudiantAnnee.objects.create(etudiant=self.etudiant, annee=self.annee)
        with self.assertRaises(IntegrityError):
            EtudiantAnnee.objects.create(etudiant=self.etudiant, annee=self.annee)

class MatiereEtudiantModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create(username='etudiant1', email='etudiant1@example.com', role='etudiant', password='password123')
        self.etudiant = Etudiant.objects.create(user=self.user)
        self.filiere = Filiere.objects.create(nom_filiere='Science')
        self.semestre = Semestre.objects.create(nom_semestre='S1')
        self.niveau = Niveau.objects.create(nom_niveau='L1')
        self.matiere = Matiere.objects.create(nom_matiere='Math', course_code='M101', filiere=self.filiere, semestre=self.semestre, niveau=self.niveau)
        self.annee = Annee.objects.create(annee='2023-2024')

    def test_unique_together(self):
        MatiereEtudiant.objects.create(etudiant=self.etudiant, matiere=self.matiere, annee=self.annee)
        with self.assertRaises(IntegrityError):
            MatiereEtudiant.objects.create(etudiant=self.etudiant, matiere=self.matiere, annee=self.annee)

class MatiereCommuneEtudiantModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create(username='etudiant1', email='etudiant1@example.com', role='etudiant', password='password123')
        self.etudiant = Etudiant.objects.create(user=self.user)
        self.filiere = Filiere.objects.create(nom_filiere='Science')
        self.semestre = Semestre.objects.create(nom_semestre='S1')
        self.niveau = Niveau.objects.create(nom_niveau='L1')
        self.matiere_commune = MatiereCommune.objects.create(nom_matiere_commune='Common Math', course_code='CM101', filiere=self.filiere, semestre=self.semestre, niveau=self.niveau)
        self.annee = Annee.objects.create(annee='2023-2024')

    def test_unique_together(self):
        MatiereCommuneEtudiant.objects.create(etudiant=self.etudiant, matiere_commune=self.matiere_commune, annee=self.annee)
        with self.assertRaises(IntegrityError):
            MatiereCommuneEtudiant.objects.create(etudiant=self.etudiant, matiere_commune=self.matiere_commune, annee=self.annee)

class ProfileEnseignantModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create(username='enseignant1', email='enseignant1@example.com', role='enseignant', password='password123')
        self.enseignant = Enseignant.objects.create(user=self.user)
        self.annee = Annee.objects.create(annee='2023-2024')
        self.filiere = Filiere.objects.create(nom_filiere='Science')
        self.semestre = Semestre.objects.create(nom_semestre='S1')
        self.niveau = Niveau.objects.create(nom_niveau='L1')
        self.matiere = Matiere.objects.create(nom_matiere='Math', course_code='M101', filiere=self.filiere, semestre=self.semestre, niveau=self.niveau)

    def test_creation_defaults(self):
        profile = ProfileEnseignant.objects.create(enseignant=self.enseignant, annee=self.annee, matiere=self.matiere)
        self.assertFalse(profile.validated)
        self.assertTrue(profile.new_entry)
        self.assertIsNotNone(profile.date_creation)

    def test_null_fields(self):
        profile = ProfileEnseignant(enseignant=self.enseignant, annee=None, matiere=None, matiere_commune=None)
        profile.full_clean()  # Should not raise

class ProfileEtudiantModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create(username='etudiant1', email='etudiant1@example.com', role='etudiant', password='password123')
        self.etudiant = Etudiant.objects.create(user=self.user)
        self.filiere = Filiere.objects.create(nom_filiere='Science')
        self.semestre = Semestre.objects.create(nom_semestre='S1')
        self.niveau = Niveau.objects.create(nom_niveau='L1')
        self.matiere = Matiere.objects.create(nom_matiere='Math', course_code='M101', filiere=self.filiere, semestre=self.semestre, niveau=self.niveau)
        self.annee = Annee.objects.create(annee='2023-2024')

    def test_unique_together(self):
        ProfileEtudiant.objects.create(etudiant=self.etudiant, filiere=self.filiere, matiere=self.matiere, semestre=self.semestre, annee=self.annee, niveau=self.niveau)
        with self.assertRaises(IntegrityError):
            ProfileEtudiant.objects.create(etudiant=self.etudiant, filiere=self.filiere, matiere=self.matiere, semestre=self.semestre, annee=self.annee, niveau=self.niveau)

    def test_null_matiere_commune(self):
        profile = ProfileEtudiant(etudiant=self.etudiant, filiere=self.filiere, matiere=self.matiere, semestre=self.semestre, annee=self.annee, niveau=self.niveau, matiere_commune=None)
        profile.full_clean()  # Should not raise