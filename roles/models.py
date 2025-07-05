from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from datetime import timedelta
from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import make_password, check_password
import uuid

# Custom manager for Matiere
class MatiereManager(models.Manager):
    def by_combination(self, filiere, semestre, niveau):
        """Filter Matiere instances by filiere, semestre, and niveau with optimized queries."""
        return self.select_related('filiere', 'semestre', 'niveau').filter(
            filiere=filiere, semestre=semestre, niveau=niveau
        )

# Custom manager for MatiereCommune
class MatiereCommuneManager(models.Manager):
    def by_combination(self,  semestre, niveau):
        """Filter MatiereCommune instances by filiere, semestre, and niveau with optimized queries."""
        return self.select_related(  'semestre', 'niveau').filter(
             semestre=semestre, niveau=niveau
        )

class User(AbstractUser):
    ROLE_CHOICES = [
        ('etudiant', 'Etudiant'),
        ('enseignant', 'Enseignant'),
        ('admin', 'Admin'),
        ('superadmin', 'Superadmin'),
    ]
    
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
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
        self.save()
    
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
    annee = models.CharField(max_length=9, unique=True)  # e.g., "2023-2024", unique and required

    class Meta:
        db_table = 'annees'

    def __str__(self):
        return self.annee

    @staticmethod
    def get_current_academic_year_str():
        """Calculate the current academic year string based on today's date."""
        today = timezone.now().date()
        year = today.year
        if today.month < 9:  # Before September
            return f"{year - 1}-{year}"
        else:  # September or later
            return f"{year}-{year + 1}"

    @classmethod
    def get_current_academic_year(cls):
        """Get or create the Annee instance for the current academic year."""
        current_year_str = cls.get_current_academic_year_str()
        annee_instance, _ = cls.objects.get_or_create(annee=current_year_str)
        return annee_instance

    @classmethod
    def get_current_academic_year_id(cls):
        """Return the ID of the current academic year."""
        return cls.get_current_academic_year().id

class Niveau(models.Model):
    nom_niveau = models.CharField(max_length=50)
    
    class Meta:
        db_table = 'niveaux'
    
    def __str__(self):
        return self.nom_niveau

class Filiere(models.Model):
    nom_filiere = models.CharField(max_length=50)
    
    class Meta:
        db_table = 'filieres'
    
    def __str__(self):
        return self.nom_filiere

class Semestre(models.Model):
    nom_semestre = models.CharField(max_length=50)
    
    class Meta:
        db_table = 'semestres'
    
    def __str__(self):
        return self.nom_semestre

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
    filiere = models.ForeignKey(Filiere, on_delete=models.SET_NULL, null=True, blank=True, db_column='id_filiere')
    niveau = models.ForeignKey(Niveau, on_delete=models.SET_NULL, null=True, blank=True, db_column='id_niveau')
    
    class Meta:
        db_table = 'etudiants'
    
    def __str__(self):
        return f"Etudiant Profile for {self.user}"

class Matiere(models.Model):
    nom_matiere = models.CharField(max_length=100)
    course_code = models.CharField(max_length=52, unique=True)  # Removed db_column='courseCode'
    filiere = models.ForeignKey(Filiere, on_delete=models.CASCADE, null=True, db_column='id_filiere')
    semestre = models.ForeignKey(Semestre, on_delete=models.CASCADE, null=True, db_column='id_semestre')
    niveau = models.ForeignKey(Niveau, on_delete=models.CASCADE, null=True, db_column='id_niveau')

    objects = MatiereManager()

    class Meta:
        db_table = 'matieres'
        indexes = [
            models.Index(fields=['filiere', 'semestre', 'niveau']),
        ]
    
    def __str__(self):
        return self.nom_matiere

class MatiereCommune(models.Model):
    nom_matiere_commune = models.CharField(max_length=100)
    course_code = models.CharField(max_length=52, unique=True)  # Removed db_column='courseCode'
    filiere = models.ForeignKey(Filiere, on_delete=models.CASCADE, null=True, db_column='id_filiere')
    semestre = models.ForeignKey(Semestre, on_delete=models.CASCADE, null=True, db_column='id_semestre')
    niveau = models.ForeignKey(Niveau, on_delete=models.CASCADE, null=True, db_column='id_niveau')

    objects = MatiereCommuneManager()

    class Meta:
        db_table = 'matieres_communes'
        indexes = [
            models.Index(fields=['filiere', 'semestre', 'niveau']),
        ]
    
    def __str__(self):
        return self.nom_matiere_commune
    

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
        constraints = [
            models.CheckConstraint(
                check=(
                    models.Q(matiere__isnull=False, matiere_commune__isnull=True) |
                    models.Q(matiere__isnull=True, matiere_commune__isnull=False)
                ),
                name='check_matiere_or_matiere_commune'
            ),
            models.UniqueConstraint(
                fields=['etudiant', 'matiere', 'annee'],
                condition=models.Q(matiere__isnull=False),
                name='unique_etudiant_matiere_annee'
            ),
            models.UniqueConstraint(
                fields=['etudiant', 'matiere_commune', 'annee'],
                condition=models.Q(matiere_commune__isnull=False),
                name='unique_etudiant_matiere_commune_annee'
            )
        ]



class EnseignantAnnee(models.Model):
    enseignant = models.ForeignKey(Enseignant, on_delete=models.CASCADE, db_column='id_enseignant')
    annee = models.ForeignKey(Annee, on_delete=models.CASCADE, null=True, blank=True, db_column='id_annee')
    
    class Meta:
        db_table = 'enseignants_annees'
        unique_together = ('enseignant', 'annee')

def get_default_annee():
    """Callable to return the current Annee instance ID for default values."""
    current_year_str = Annee.get_current_academic_year_str()
    annee_instance, _ = Annee.objects.get_or_create(annee=current_year_str)
    return annee_instance.id

class EtudiantAnnee(models.Model):
    etudiant = models.ForeignKey(Etudiant, on_delete=models.CASCADE, db_column='id_etudiant')
    annee = models.ForeignKey(
        Annee,
        on_delete=models.CASCADE,
        null=False,
        blank=False,
        db_column='id_annee',
        default=get_default_annee
    )
    
    class Meta:
        db_table = 'etudiants_annees'
        unique_together = ('etudiant', 'annee')

class MatiereEtudiant(models.Model):
    etudiant = models.ForeignKey(Etudiant, on_delete=models.CASCADE, db_column='id_etudiant')
    matiere = models.ForeignKey(Matiere, on_delete=models.CASCADE, db_column='id_matiere')
    annee = models.ForeignKey(Annee, on_delete=models.CASCADE, null=True, blank=True, db_column='id_annee')
    
    class Meta:
        db_table = 'matieres_etudiants'
        unique_together = ('etudiant', 'matiere', 'annee')

class MatiereCommuneEtudiant(models.Model):
    etudiant = models.ForeignKey(Etudiant, on_delete=models.CASCADE, db_column='id_etudiant')
    matiere_commune = models.ForeignKey(MatiereCommune, on_delete=models.CASCADE, db_column='id_matiere_commune')
    annee = models.ForeignKey(Annee, on_delete=models.CASCADE, null=True, blank=True, db_column='id_annee')
    
    class Meta:
        db_table = 'matieres_communes_etudiants'
        unique_together = ('etudiant', 'matiere_commune', 'annee')

class ProfileEnseignant(models.Model):
    enseignant = models.ForeignKey(Enseignant, on_delete=models.CASCADE, db_column='id_enseignant')
    annee = models.ForeignKey(Annee, on_delete=models.CASCADE, null=True, blank=True, db_column='id_annee')
    matiere = models.ForeignKey(Matiere, on_delete=models.CASCADE, null=True, blank=True, db_column='id_matiere')
    matiere_commune = models.ForeignKey(MatiereCommune, on_delete=models.CASCADE, null=True, blank=True, db_column='id_matiere_commune')
    validated = models.BooleanField(default=False)
    date_creation = models.DateTimeField(auto_now_add=True)
    new_entry = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'profile_enseignant'

class ProfileEtudiant(models.Model):
    etudiant = models.ForeignKey(Etudiant, on_delete=models.CASCADE, db_column='id_etudiant')
    filiere = models.ForeignKey(Filiere, on_delete=models.CASCADE, db_column='id_filiere')
    semestre = models.ForeignKey(Semestre, on_delete=models.CASCADE, db_column='id_semestre')
    annee = models.ForeignKey(
        Annee,
        on_delete=models.CASCADE,
        null=False,
        blank=False,
        db_column='id_annee',
        default=get_default_annee
    )
    niveau = models.ForeignKey(Niveau, on_delete=models.CASCADE, db_column='id_niveau')

    class Meta:
        db_table = 'profile_etudiant'
        unique_together = ('etudiant', 'annee')

