from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from datetime import timedelta
from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import make_password, check_password
import uuid

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
    
    class Meta:
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['role']),
        ]
    
    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.role})"
    
    def get_redirect_url(self):
        redirect_urls = {
            'etudiant': '/etudiant/dashboard/',
            'enseignant': '/enseignant/dashboard/',
            'admin': '/admin/panel/',
            'superadmin': '/superadmin/panel/',
        }
        return redirect_urls.get(self.role, '/signin/')
    
    def clean(self):
        if not self.phone_number.isdigit():
            raise ValidationError("Phone number must contain only digits.")

class Invitation(models.Model):
    ROLE_CHOICES = User.ROLE_CHOICES
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('expired', 'Expired'),
        ('invalidated', 'Invalidated'),
    ]
    
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    pin = models.CharField(max_length=128)
    email = models.EmailField()
    attempt_count = models.IntegerField(default=0)
    inviter = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_invitations')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    accepted_by = models.OneToOneField(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name='invitation'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    
    class Meta:
        indexes = [
            models.Index(fields=['token']),
            models.Index(fields=['status']),
        ]
    
    def __str__(self):
        return f"Invitation for {self.role} to {self.email} by {self.inviter}"
    
    def set_pin(self, raw_pin):
        if len(raw_pin) != 6 or not raw_pin.isdigit():
            raise ValidationError("PIN must be a 6-digit number.")
        self.pin = make_password(raw_pin)
    
    def check_pin(self, raw_pin):
        return check_password(raw_pin, self.pin)
    
    def is_expired(self):
        return timezone.now() > self.expires_at
    
    def save(self, *args, **kwargs):
        if self.pk is None:
            if self.inviter.role not in ['superadmin', 'admin']:
                raise ValidationError("Only superadmins and admins can send invitations.")
            if self.inviter.role == 'admin' and self.role != 'enseignant':
                raise ValidationError("Admins can only invite teachers.")
            if self.role == 'etudiant':
                raise ValidationError("Cannot send invitations for etudiant role.")
            if not self.expires_at:
                self.expires_at = timezone.now() + timedelta(hours=24)
        super().save(*args, **kwargs)

class Annee(models.Model):
    annee = models.CharField(max_length=9, null=True, blank=True)  # Added blank=True

    class Meta:
        db_table = 'annees'

class Filiere(models.Model):
    nom_filiere = models.CharField(max_length=50)

    class Meta:
        db_table = 'filieres'

class Niveau(models.Model):
    nom_niveau = models.CharField(max_length=50)

    class Meta:
        db_table = 'niveaux'

class Semestre(models.Model):
    nom_semestre = models.CharField(max_length=50)

    class Meta:
        db_table = 'semestres'

class Admin(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='admin_profile')
    date_creation = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'admins'
    
    def __str__(self):
        return f"Admin Profile for {self.user}"

class Enseignant(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='enseignant_profile')
    date_creation = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'enseignants'
    
    def __str__(self):
        return f"Enseignant Profile for {self.user}"

class Etudiant(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='etudiant_profile')
    date_creation = models.DateTimeField(auto_now_add=True)
    filiere = models.CharField(max_length=100, null=True, blank=True)
    niveau = models.CharField(max_length=50, null=True, blank=True)
    
    class Meta:
        db_table = 'etudiants'
    
    def __str__(self):
        return f"Etudiant Profile for {self.user}"

class Matiere(models.Model):
    nom_matiere = models.CharField(max_length=100)
    course_code = models.CharField(max_length=52, unique=True, db_column='courseCode')
    filiere = models.ForeignKey(Filiere, on_delete=models.CASCADE, null=True, db_column='id_filiere')
    semestre = models.ForeignKey(Semestre, on_delete=models.CASCADE, null=True, db_column='id_semestre')
    niveau = models.ForeignKey(Niveau, on_delete=models.CASCADE, null=True, db_column='id_niveau')

    class Meta:
        db_table = 'matieres'

class MatiereCommune(models.Model):
    nom_matiere_commune = models.CharField(max_length=100)
    course_code = models.CharField(max_length=52, unique=True, db_column='courseCode')
    filiere = models.ForeignKey(Filiere, on_delete=models.CASCADE, null=True, db_column='id_filiere')
    semestre = models.ForeignKey(Semestre, on_delete=models.CASCADE, null=True, db_column='id_semestre')
    niveau = models.ForeignKey(Niveau, on_delete=models.CASCADE, null=True, db_column='id_niveau')

    class Meta:
        db_table = 'matieres_communes'

class Note(models.Model):
    etudiant = models.ForeignKey(Etudiant, on_delete=models.CASCADE, db_column='id_etudiant')
    matiere = models.ForeignKey(Matiere, on_delete=models.CASCADE, null=True, blank=True, db_column='id_matiere')
    matiere_commune = models.ForeignKey(MatiereCommune, on_delete=models.CASCADE, null=True, blank=True, db_column='id_matiere_commune')
    cc_note = models.FloatField()
    normal_note = models.FloatField()
    note_final = models.FloatField()
    annee = models.ForeignKey(Annee, on_delete=models.CASCADE, null=True, blank=True, db_column='id_annee')

    class Meta:
        db_table = 'notes'
        unique_together = ('etudiant', 'matiere', 'annee')  # Exclude matiere_commune if often NULL

class EnseignantAnnee(models.Model):
    enseignant = models.ForeignKey(Enseignant, on_delete=models.CASCADE, db_column='id_enseignant')
    annee = models.ForeignKey(Annee, on_delete=models.CASCADE, null=True, blank=True, db_column='id_annee')  # Added blank=True

    class Meta:
        db_table = 'enseignants_annees'
        unique_together = ('enseignant', 'annee')

class EtudiantAnnee(models.Model):
    etudiant = models.ForeignKey(Etudiant, on_delete=models.CASCADE, db_column='id_etudiant')
    annee = models.ForeignKey(Annee, on_delete=models.CASCADE, null=True, blank=True, db_column='id_annee')  # Added blank=True

    class Meta:
        db_table = 'etudiants_annees'
        unique_together = ('etudiant', 'annee')

class MatiereEtudiant(models.Model):
    etudiant = models.ForeignKey(Etudiant, on_delete=models.CASCADE, db_column='id_etudiant')
    matiere = models.ForeignKey(Matiere, on_delete=models.CASCADE, db_column='id_matiere')
    annee = models.ForeignKey(Annee, on_delete=models.CASCADE, null=True, blank=True, db_column='id_annee')  # Added blank=True

    class Meta:
        db_table = 'matieres_etudiants'
        unique_together = ('etudiant', 'matiere', 'annee')

class MatiereCommuneEtudiant(models.Model):
    etudiant = models.ForeignKey(Etudiant, on_delete=models.CASCADE, db_column='id_etudiant')
    matiere_commune = models.ForeignKey(MatiereCommune, on_delete=models.CASCADE, db_column='id_matiere_commune')
    annee = models.ForeignKey(Annee, on_delete=models.CASCADE, null=True, blank=True, db_column='id_annee')  # Added blank=True

    class Meta:
        db_table = 'matieres_communes_etudiants'
        unique_together = ('etudiant', 'matiere_commune', 'annee')

class ProfileEnseignant(models.Model):
    enseignant = models.ForeignKey(Enseignant, on_delete=models.CASCADE, db_column='id_enseignant')
    annee = models.ForeignKey(Annee, on_delete=models.CASCADE, null=True, blank=True, db_column='id_annee')  # Added blank=True
    matiere = models.ForeignKey(Matiere, on_delete=models.CASCADE, null=True, blank=True, db_column='id_matiere')  # Added blank=True
    matiere_commune = models.ForeignKey(MatiereCommune, on_delete=models.CASCADE, null=True, blank=True, db_column='id_matiere_commune')  # Added blank=True
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
    annee = models.ForeignKey(Annee, on_delete=models.CASCADE, null=True, blank=True, db_column='id_annee')  # Added blank=True
    niveau = models.ForeignKey(Niveau, on_delete=models.CASCADE, db_column='id_niveau')
    matiere_commune = models.ForeignKey(MatiereCommune, on_delete=models.CASCADE, null=True, blank=True, db_column='id_matiere_commune')  # Added blank=True

    class Meta:
        db_table = 'profile_etudiant'
        unique_together = ('etudiant', 'annee')