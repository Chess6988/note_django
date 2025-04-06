from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from datetime import timedelta
from django.core.exceptions import ValidationError

# User Model with Roles
class User(AbstractUser):
    ROLE_CHOICES = [
        ('etudiant', 'Etudiant'),
        ('enseignant', 'Enseignant'),
        ('admin', 'Admin'),
        ('superadmin', 'Superadmin'),
    ]
    
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    phone_number = models.CharField(max_length=15, default='0000000000')
    email = models.EmailField(unique=True)
    
    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.role})"
    
    def get_redirect_url(self):
        if self.role == 'etudiant':
            return '/etudiant/dashboard/'
        elif self.role == 'enseignant':
            return '/enseignant/dashboard/'
        elif self.role == 'admin':
            return '/admin/panel/'
        elif self.role == 'superadmin':
            return '/superadmin/panel/'
        else:
            return '/role-not-found/'

# Invitation Model
class Invitation(models.Model):
    role = models.CharField(max_length=20, choices=User.ROLE_CHOICES)
    pin = models.CharField(max_length=10, unique=True)
    inviter = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_invitations')
    invitee_email = models.EmailField()
    status = models.CharField(max_length=20, default='pending')
    accepted_by = models.OneToOneField(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='invitation'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    
    def __str__(self):
        return f"Invitation for {self.role} to {self.invitee_email} by {self.inviter}"
    
    def is_expired(self):
        return timezone.now() > self.expires_at
    
    def save(self, *args, **kwargs):
        if self.pk is None:
            if self.inviter.role not in ['superadmin', 'admin']:
                raise ValidationError("Only superadmins and admins can send invitations.")
            if self.inviter.role == 'admin' and self.role != 'admin':
                raise ValidationError("Admins can only invite users to become admins.")
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=1)
        super().save(*args, **kwargs)

# Annee (Years)
class Annee(models.Model):
    annee = models.CharField(max_length=9, null=True)

    class Meta:
        db_table = 'annees'

# Filiere (Fields of Study)
class Filiere(models.Model):
    nom_filiere = models.CharField(max_length=50)

    class Meta:
        db_table = 'filieres'

# Niveau (Levels)
class Niveau(models.Model):
    nom_niveau = models.CharField(max_length=50)

    class Meta:
        db_table = 'niveaux'

# Semestre (Semesters)
class Semestre(models.Model):
    nom_semestre = models.CharField(max_length=50)

    class Meta:
        db_table = 'semestres'

# Admin Profile
class Admin(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='admin_profile')
    date_creation = models.DateTimeField(auto_now_add=True)
 
    class Meta:
        db_table = 'admins'

# Enseignant (Teacher) Profile
class Enseignant(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='enseignant_profile')
    date_creation = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'enseignants'

# Etudiant (Student) Profile
class Etudiant(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='etudiant_profile')
    date_creation = models.DateTimeField(auto_now_add=True)
    filiere = models.ForeignKey(Filiere, on_delete=models.CASCADE, null=True, db_column='id_filiere')
    niveau = models.ForeignKey(Niveau, on_delete=models.CASCADE, null=True, db_column='id_niveau')
   
    class Meta:
        db_table = 'etudiants'

# Matiere (Courses)
class Matiere(models.Model):
    nom_matiere = models.CharField(max_length=100)
    course_code = models.CharField(max_length=52, unique=True, db_column='courseCode')
    filiere = models.ForeignKey(Filiere, on_delete=models.CASCADE, null=True, db_column='id_filiere')
    semestre = models.ForeignKey(Semestre, on_delete=models.CASCADE, null=True, db_column='id_semestre')
    niveau = models.ForeignKey(Niveau, on_delete=models.CASCADE, null=True, db_column='id_niveau')

    class Meta:
        db_table = 'matieres'

# MatiereCommune (Common Courses)
class MatiereCommune(models.Model):
    nom_matiere_commune = models.CharField(max_length=100)
    course_code = models.CharField(max_length=52, unique=True, db_column='courseCode')
    filiere = models.ForeignKey(Filiere, on_delete=models.CASCADE, null=True, db_column='id_filiere')
    semestre = models.ForeignKey(Semestre, on_delete=models.CASCADE, null=True, db_column='id_semestre')
    niveau = models.ForeignKey(Niveau, on_delete=models.CASCADE, null=True, db_column='id_niveau')

    class Meta:
        db_table = 'matieres_communes'

# Note (Grades)
class Note(models.Model):
    etudiant = models.ForeignKey(Etudiant, on_delete=models.CASCADE, db_column='id_etudiant')
    matiere = models.ForeignKey(Matiere, on_delete=models.CASCADE, null=True, db_column='id_matiere')
    matiere_commune = models.ForeignKey(MatiereCommune, on_delete=models.CASCADE, null=True, db_column='id_matiere_commune')
    cc_note = models.FloatField()
    normal_note = models.FloatField()
    note_final = models.FloatField()
    annee = models.ForeignKey(Annee, on_delete=models.CASCADE, null=True, db_column='id_annee')

    class Meta:
        db_table = 'notes'
        unique_together = ('etudiant', 'matiere', 'matiere_commune', 'annee')

# Through Models for Many-to-Many Relationships
# Enseignant Through Models
class EnseignantAnnee(models.Model):
    enseignant = models.ForeignKey(Enseignant, on_delete=models.CASCADE, db_column='id_enseignant')
    annee = models.ForeignKey(Annee, on_delete=models.CASCADE, db_column='id_annee', null=True)

    class Meta:
        db_table = 'enseignants_annees'
        unique_together = ('enseignant', 'annee')

# Etudiant Through Models
class EtudiantAnnee(models.Model):
    etudiant = models.ForeignKey(Etudiant, on_delete=models.CASCADE, db_column='id_etudiant')
    annee = models.ForeignKey(Annee, on_delete=models.CASCADE, db_column='id_annee', null=True)

    class Meta:
        db_table = 'etudiants_annees'
        unique_together = ('etudiant', 'annee')

class MatiereEtudiant(models.Model):
    etudiant = models.ForeignKey(Etudiant, on_delete=models.CASCADE, db_column='id_etudiant')
    matiere = models.ForeignKey(Matiere, on_delete=models.CASCADE, db_column='id_matiere')
    annee = models.ForeignKey(Annee, on_delete=models.CASCADE, db_column='id_annee', null=True)

    class Meta:
        db_table = 'matieres_etudiants'
        unique_together = ('etudiant', 'matiere', 'annee')

class MatiereCommuneEtudiant(models.Model):
    etudiant = models.ForeignKey(Etudiant, on_delete=models.CASCADE, db_column='id_etudiant')
    matiere_commune = models.ForeignKey(MatiereCommune, on_delete=models.CASCADE, db_column='id_matiere_commune')
    annee = models.ForeignKey(Annee, on_delete=models.CASCADE, db_column='id_annee', null=True)

    class Meta:
        db_table = 'matieres_communes_etudiants'
        unique_together = ('etudiant', 'matiere_commune', 'annee')

# New Models Added
class ProfileEnseignant(models.Model):
    enseignant = models.ForeignKey(Enseignant, on_delete=models.CASCADE, db_column='id_enseignant')
    annee = models.ForeignKey(Annee, on_delete=models.CASCADE, db_column='id_annee', null=True)
    matiere = models.ForeignKey(Matiere, on_delete=models.CASCADE, null=True, db_column='id_matiere')
    matiere_commune = models.ForeignKey(MatiereCommune, on_delete=models.CASCADE, null=True, db_column='id_matiere_commune')
    validated = models.BooleanField(default=False)
    date_creation = models.DateTimeField(auto_now_add=True)
    new_entry = models.BooleanField(default=True)

    class Meta:
        db_table = 'profile_enseignant'

class ProfileEtudiant(models.Model):
    etudiant = models.ForeignKey(Etudiant, on_delete=models.CASCADE, db_column='id_etudiant')
    filiere = models.ForeignKey(Filiere, on_delete=models.CASCADE, db_column='id_filiere')
    matiere = models.ForeignKey(Matiere, on_delete=models.CASCADE, db_column='id_matiere')
    semestre = models.ForeignKey(Semestre, on_delete=models.CASCADE, db_column='id_semestre')
    annee = models.ForeignKey(Annee, on_delete=models.CASCADE, db_column='id_annee', null=True)
    niveau = models.ForeignKey(Niveau, on_delete=models.CASCADE, db_column='id_niveau')
    matiere_commune = models.ForeignKey(MatiereCommune, on_delete=models.CASCADE, null=True, db_column='id_matiere_commune')
    annee = models.ForeignKey(Annee, on_delete=models.CASCADE, db_column='id_annee', null=True)

    class Meta:
        db_table = 'profile_etudiant'