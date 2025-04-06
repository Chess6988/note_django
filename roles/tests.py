from django.test import TestCase
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
class UserModelTest(TestCase):
    def test_user_creation(self):
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
        self.assertEqual(str(user), 'John Doe (etudiant)')

    def test_unique_email(self):
        """Test that the email field enforces uniqueness."""
        User.objects.create_user(
            username='user1',
            email='unique@example.com',
            password='pass',
            role='admin'
        )
        with self.assertRaises(IntegrityError):
            User.objects.create_user(
                username='user2',
                email='unique@example.com',
                password='pass',
                role='admin'
            )

    def test_get_redirect_url(self):
        """Test that get_redirect_url returns the correct URL based on role."""
        roles_urls = {
            'etudiant': '/etudiant/dashboard/',
            'enseignant': '/enseignant/dashboard/',
            'admin': '/admin/panel/',
            'superadmin': '/superadmin/panel/'
        }
        for role, expected_url in roles_urls.items():
            user = User(role=role)
            self.assertEqual(user.get_redirect_url(), expected_url)

# Invitation Model Tests
class InvitationModelTest(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='adminpass',
            role='admin'
        )
        self.superadmin = User.objects.create_user(
            username='superadmin',
            email='super@example.com',
            password='superpass',
            role='superadmin'
        )

    def test_invitation_creation(self):
        """Test that an invitation is created with correct attributes."""
        invitation = Invitation.objects.create(
            role='admin',
            pin='123456',
            inviter=self.admin,
            invitee_email='invitee@example.com',
            expires_at=timezone.now() + timedelta(minutes=1)
        )
        self.assertEqual(invitation.status, 'pending')
        self.assertFalse(invitation.is_expired())

    def test_invitation_expiration(self):
        """Test the is_expired method."""
        invitation = Invitation.objects.create(
            role='admin',
            pin='654321',
            inviter=self.admin,
            invitee_email='invitee@example.com',
            expires_at=timezone.now() - timedelta(minutes=1)  # Already expired
        )
        self.assertTrue(invitation.is_expired())

    def test_save_validation_admin_role(self):
        """Test that admins can only invite other admins."""
        with self.assertRaises(ValidationError):
            Invitation.objects.create(
                role='etudiant',
                pin='111111',
                inviter=self.admin,
                invitee_email='student@example.com'
            )

    def test_save_validation_non_admin(self):
        """Test that only admins and superadmins can send invitations."""
        non_admin = User.objects.create_user(
            username='teacher',
            email='teacher@example.com',
            password='pass',
            role='enseignant'
        )
        with self.assertRaises(ValidationError):
            Invitation.objects.create(
                role='enseignant',
                pin='222222',
                inviter=non_admin,
                invitee_email='newteacher@example.com'
            )

# Basic Model Tests (Annee, Filiere, Niveau, Semestre)
class BasicModelTests(TestCase):
    def test_annee_creation(self):
        """Test Annee model creation."""
        annee = Annee.objects.create(annee='2023-2024')
        self.assertEqual(Annee.objects.count(), 1)
        self.assertEqual(annee.annee, '2023-2024')

    def test_filiere_creation(self):
        """Test Filiere model creation."""
        filiere = Filiere.objects.create(nom_filiere='Informatique')
        self.assertEqual(Filiere.objects.count(), 1)
        self.assertEqual(filiere.nom_filiere, 'Informatique')

    def test_niveau_creation(self):
        """Test Niveau model creation."""
        niveau = Niveau.objects.create(nom_niveau='L1')
        self.assertEqual(Niveau.objects.count(), 1)
        self.assertEqual(niveau.nom_niveau, 'L1')

    def test_semestre_creation(self):
        """Test Semestre model creation."""
        semestre = Semestre.objects.create(nom_semestre='S1')
        self.assertEqual(Semestre.objects.count(), 1)
        self.assertEqual(semestre.nom_semestre, 'S1')

# Admin Profile Tests
class AdminModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='pass',
            role='admin'
        )
        self.admin = Admin.objects.create(user=self.user)
        self.annee = Annee.objects.create(annee='2023-2024')
        self.filiere = Filiere.objects.create(nom_filiere='Informatique')
        self.semestre = Semestre.objects.create(nom_semestre='S1')

    def test_admin_creation(self):
        """Test that an admin profile is created with a one-to-one relationship."""
        self.assertEqual(self.admin.user, self.user)
        self.assertIsNotNone(self.admin.date_creation)

    def test_many_to_many_relationships(self):
        """Test many-to-many relationships with Annee, Filiere, and Semestre."""
        AdminAnnee.objects.create(admin=self.admin, annee=self.annee)
        AdminFiliere.objects.create(admin=self.admin, filiere=self.filiere)
        AdminSemestre.objects.create(admin=self.admin, semestre=self.semestre)
        self.assertIn(self.annee, self.admin.annees.all())
        self.assertIn(self.filiere, self.admin.filieres.all())
        self.assertIn(self.semestre, self.admin.semestres.all())

# Enseignant Profile Tests
class EnseignantModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='teacher',
            email='teacher@example.com',
            password='pass',
            role='enseignant'
        )
        self.enseignant = Enseignant.objects.create(user=self.user)
        self.annee = Annee.objects.create(annee='2023-2024')
        self.filiere = Filiere.objects.create(nom_filiere='Informatique')
        self.niveau = Niveau.objects.create(nom_niveau='L1')
        self.semestre = Semestre.objects.create(nom_semestre='S1')
        self.matiere = Matiere.objects.create(
            nom_matiere='Math',
            course_code='MATH101',
            filiere=self.filiere,
            semestre=self.semestre,
            niveau=self.niveau
        )
        self.matiere_commune = MatiereCommune.objects.create(
            nom_matiere_commune='Physics',
            course_code='PHY101',
            filiere=self.filiere,
            semestre=self.semestre,
            niveau=self.niveau
        )

    def test_enseignant_creation(self):
        """Test that an enseignant profile is created."""
        self.assertEqual(self.enseignant.user, self.user)

    def test_many_to_many_relationships(self):
        """Test many-to-many relationships with Annee, Filiere, Matiere, etc."""
        EnseignantAnnee.objects.create(enseignant=self.enseignant, annee=self.annee)
        EnseignantFiliere.objects.create(enseignant=self.enseignant, filiere=self.filiere)
        EnseignantMatiere.objects.create(enseignant=self.enseignant, matiere=self.matiere)
        EnseignantMatiereCommune.objects.create(enseignant=self.enseignant, matiere_commune=self.matiere_commune)
        EnseignantNiveau.objects.create(enseignant=self.enseignant, niveau=self.niveau)
        EnseignantSemestre.objects.create(enseignant=self.enseignant, semestre=self.semestre)
        self.assertIn(self.annee, self.enseignant.annees.all())
        self.assertIn(self.filiere, self.enseignant.filieres.all())
        self.assertIn(self.matiere, self.enseignant.matieres.all())
        self.assertIn(self.matiere_commune, self.enseignant.matieres_communes.all())
        self.assertIn(self.niveau, self.enseignant.niveaux.all())
        self.assertIn(self.semestre, self.enseignant.semestres.all())

# Etudiant Profile Tests
class EtudiantModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='student',
            email='student@example.com',
            password='pass',
            role='etudiant'
        )
        self.filiere = Filiere.objects.create(nom_filiere='Informatique')
        self.niveau = Niveau.objects.create(nom_niveau='L1')
        self.etudiant = Etudiant.objects.create(user=self.user, filiere=self.filiere, niveau=self.niveau)
        self.annee = Annee.objects.create(annee='2023-2024')
        self.semestre = Semestre.objects.create(nom_semestre='S1')
        self.matiere = Matiere.objects.create(
            nom_matiere='Math',
            course_code='MATH101',
            filiere=self.filiere,
            semestre=self.semestre,
            niveau=self.niveau
        )
        self.matiere_commune = MatiereCommune.objects.create(
            nom_matiere_commune='Physics',
            course_code='PHY101',
            filiere=self.filiere,
            semestre=self.semestre,
            niveau=self.niveau
        )

    def test_etudiant_creation(self):
        """Test that an etudiant profile is created with foreign keys."""
        self.assertEqual(self.etudiant.user, self.user)
        self.assertEqual(self.etudiant.filiere, self.filiere)
        self.assertEqual(self.etudiant.niveau, self.niveau)

    def test_many_to_many_relationships(self):
        """Test many-to-many relationships with Annee, Semestre, Matiere, etc."""
        EtudiantAnnee.objects.create(etudiant=self.etudiant, annee=self.annee)
        EtudiantSemestre.objects.create(etudiant=self.etudiant, semestre=self.semestre)
        MatiereEtudiant.objects.create(etudiant=self.etudiant, matiere=self.matiere)
        MatiereCommuneEtudiant.objects.create(etudiant=self.etudiant, matiere_commune=self.matiere_commune)
        self.assertIn(self.annee, self.etudiant.annees.all())
        self.assertIn(self.semestre, self.etudiant.semestres.all())
        self.assertIn(self.matiere, self.etudiant.matieres.all())
        self.assertIn(self.matiere_commune, self.etudiant.matieres_communes.all())

# Matiere and MatiereCommune Tests
class MatiereModelTest(TestCase):
    def setUp(self):
        self.filiere = Filiere.objects.create(nom_filiere='Informatique')
        self.semestre = Semestre.objects.create(nom_semestre='S1')
        self.niveau = Niveau.objects.create(nom_niveau='L1')

    def test_matiere_creation(self):
        """Test that a matiere is created with unique course_code."""
        matiere = Matiere.objects.create(
            nom_matiere='Math',
            course_code='MATH101',
            filiere=self.filiere,
            semestre=self.semestre,
            niveau=self.niveau
        )
        self.assertEqual(matiere.nom_matiere, 'Math')

    def test_unique_course_code(self):
        """Test that course_code is unique in Matiere."""
        Matiere.objects.create(
            nom_matiere='Math',
            course_code='MATH101',
            filiere=self.filiere,
            semestre=self.semestre,
            niveau=self.niveau
        )
        with self.assertRaises(IntegrityError):
            Matiere.objects.create(
                nom_matiere='Physics',
                course_code='MATH101',
                filiere=self.filiere,
                semestre=self.semestre,
                niveau=self.niveau
            )

    def test_matiere_commune_creation(self):
        """Test that a matiere_commune is created with unique course_code."""
        matiere_commune = MatiereCommune.objects.create(
            nom_matiere_commune='Physics',
            course_code='PHY101',
            filiere=self.filiere,
            semestre=self.semestre,
            niveau=self.niveau
        )
        self.assertEqual(matiere_commune.nom_matiere_commune, 'Physics')

    def test_unique_course_code_matiere_commune(self):
        """Test that course_code is unique in MatiereCommune."""
        MatiereCommune.objects.create(
            nom_matiere_commune='Physics',
            course_code='PHY101',
            filiere=self.filiere,
            semestre=self.semestre,
            niveau=self.niveau
        )
        with self.assertRaises(IntegrityError):
            MatiereCommune.objects.create(
                nom_matiere_commune='Chemistry',
                course_code='PHY101',
                filiere=self.filiere,
                semestre=self.semestre,
                niveau=self.niveau
            )

# Note Model Tests
class NoteModelTest(TestCase):
    def setUp(self):
        self.filiere = Filiere.objects.create(nom_filiere='Informatique')
        self.niveau = Niveau.objects.create(nom_niveau='L1')
        self.semestre = Semestre.objects.create(nom_semestre='S1')
        self.user = User.objects.create_user(
            username='student',
            email='student@example.com',
            password='testpass',
            role='etudiant'
        )
        self.etudiant = Etudiant.objects.create(user=self.user, filiere=self.filiere, niveau=self.niveau)
        self.matiere = Matiere.objects.create(
            nom_matiere='Math',
            course_code='MATH101',
            filiere=self.filiere,
            semestre=self.semestre,
            niveau=self.niveau
        )
        self.matiere_commune = MatiereCommune.objects.create(
            nom_matiere_commune='Physics',
            course_code='PHY101',
            filiere=self.filiere,
            semestre=self.semestre,
            niveau=self.niveau
        )
        self.annee = Annee.objects.create(annee='2023-2024')

    def test_unique_together_constraint(self):
        """Test that the unique_together constraint is enforced in Note."""
        Note.objects.create(
            etudiant=self.etudiant,
            matiere=self.matiere,
            matiere_commune=self.matiere_commune,
            cc_note=15.0,
            normal_note=16.0,
            note_final=15.5,
            annee=self.annee
        )
        with self.assertRaises(IntegrityError):
            Note.objects.create(
                etudiant=self.etudiant,
                matiere=self.matiere,
                matiere_commune=self.matiere_commune,
                cc_note=14.0,
                normal_note=15.0,
                note_final=14.5,
                annee=self.annee
            )

# Through Model Tests (Example for AdminAnnee)
class ThroughModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='pass',
            role='admin'
        )
        self.admin = Admin.objects.create(user=self.user)
        self.annee = Annee.objects.create(annee='2023-2024')

    def test_admin_annee_unique_together(self):
        """Test that AdminAnnee enforces unique_together."""
        AdminAnnee.objects.create(admin=self.admin, annee=self.annee)
        with self.assertRaises(IntegrityError):
            AdminAnnee.objects.create(admin=self.admin, annee=self.annee)