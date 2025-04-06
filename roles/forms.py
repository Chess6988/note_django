from django import forms
from django.core.exceptions import ValidationError
from .models import (
    User, Invitation, Annee, Filiere, Niveau, Semestre, Admin, Enseignant, Etudiant,
    Matiere, MatiereCommune, Note, EnseignantAnnee, EtudiantAnnee, MatiereEtudiant,
    MatiereCommuneEtudiant, ProfileEnseignant, ProfileEtudiant
)

### User Form
class UserForm(forms.ModelForm):
    """Form for the User model, reflecting fields from UserAdmin."""
    class Meta:
        model = User
        fields = [
            'username', 'email', 'password', 'first_name', 'last_name',
            'phone_number', 'role', 'is_active', 'is_staff', 'is_superuser'
        ]
        widgets = {
            'password': forms.PasswordInput(),  # Secure input for password
        }

### Invitation Form
class InvitationForm(forms.ModelForm):
    """Form for the Invitation model, with fields from InvitationAdmin."""
    class Meta:
        model = Invitation
        fields = ['role', 'pin', 'inviter', 'invitee_email', 'status', 'expires_at']

### Admin Form
class AdminForm(forms.ModelForm):
    """Form for the Admin model, based on AdminAdmin."""
    class Meta:
        model = Admin
        fields = ['user']  # date_creation is auto-populated, so excluded

### Enseignant Form
class EnseignantForm(forms.ModelForm):
    """Form for the Enseignant model, based on EnseignantAdmin."""
    class Meta:
        model = Enseignant
        fields = ['user']  # date_creation is auto-populated, so excluded

### Etudiant Form
class EtudiantForm(forms.ModelForm):
    """Form for the Etudiant model, reflecting EtudiantAdmin."""
    class Meta:
        model = Etudiant
        fields = ['user', 'filiere', 'niveau']  # date_creation excluded

### Matiere Form
class MatiereForm(forms.ModelForm):
    """Form for the Matiere model, based on MatiereAdmin."""
    class Meta:
        model = Matiere
        fields = ['nom_matiere', 'course_code', 'filiere', 'semestre', 'niveau']

### MatiereCommune Form
class MatiereCommuneForm(forms.ModelForm):
    """Form for the MatiereCommune model, based on MatiereCommuneAdmin."""
    class Meta:
        model = MatiereCommune
        fields = ['nom_matiere_commune', 'course_code', 'filiere', 'semestre', 'niveau']

### Note Form
class NoteForm(forms.ModelForm):
    """Form for the Note model, reflecting NoteAdmin."""
    class Meta:
        model = Note
        fields = ['etudiant', 'matiere', 'matiere_commune', 'cc_note', 'normal_note', 'note_final', 'annee']

### ProfileEnseignant Form
class ProfileEnseignantForm(forms.ModelForm):
    """Form for the ProfileEnseignant model, based on ProfileEnseignantAdmin."""
    class Meta:
        model = ProfileEnseignant
        fields = ['enseignant', 'annee', 'matiere', 'matiere_commune', 'validated', 'new_entry']
        # date_creation is auto-populated, so excluded

### ProfileEtudiant Form
class ProfileEtudiantForm(forms.ModelForm):
    """Form for the ProfileEtudiant model, based on ProfileEtudiantAdmin."""
    class Meta:
        model = ProfileEtudiant
        fields = ['etudiant', 'filiere', 'matiere', 'semestre', 'annee', 'niveau', 'matiere_commune']

### Forms for Models without Custom Admin Classes
# These use all fields since no specific admin customization is provided

class AnneeForm(forms.ModelForm):
    """Form for the Annee model."""
    class Meta:
        model = Annee
        fields = '__all__'

class FiliereForm(forms.ModelForm):
    """Form for the Filiere model."""
    class Meta:
        model = Filiere
        fields = '__all__'

class NiveauForm(forms.ModelForm):
    """Form for the Niveau model."""
    class Meta:
        model = Niveau
        fields = '__all__'

class SemestreForm(forms.ModelForm):
    """Form for the Semestre model."""
    class Meta:
        model = Semestre
        fields = '__all__'

class EnseignantAnneeForm(forms.ModelForm):
    """Form for the EnseignantAnnee model."""
    class Meta:
        model = EnseignantAnnee
        fields = '__all__'

class EtudiantAnneeForm(forms.ModelForm):
    """Form for the EtudiantAnnee model."""
    class Meta:
        model = EtudiantAnnee
        fields = '__all__'

class MatiereEtudiantForm(forms.ModelForm):
    """Form for the MatiereEtudiant model."""
    class Meta:
        model = MatiereEtudiant
        fields = '__all__'

class MatiereCommuneEtudiantForm(forms.ModelForm):
    """Form for the MatiereCommuneEtudiant model."""
    class Meta:
        model = MatiereCommuneEtudiant
        fields = '__all__'