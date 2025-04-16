from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import (
    User, Invitation, Annee, Filiere, Niveau, Semestre, Admin, Enseignant, Etudiant,
    Matiere, MatiereCommune, Note, EnseignantAnnee, EtudiantAnnee, MatiereEtudiant,
    MatiereCommuneEtudiant, ProfileEnseignant, ProfileEtudiant
)

# Custom Forms to Override Initial Values

class UserAdminForm(forms.ModelForm):
    """Custom form for User model to override initial values."""
    class Meta:
        model = User
        fields = '__all__'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not self.instance.pk:  # Only for new instances (add form)
            self.initial['phone_number'] = ''  # Override default to empty

class InvitationAdminForm(forms.ModelForm):
    """Custom form for Invitation model to override initial values."""
    class Meta:
        model = Invitation
        fields = '__all__'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not self.instance.pk:
            self.initial['pin'] = ''  # Assuming 'pin' might have a default; adjust as needed

class AdminAdminForm(forms.ModelForm):
    """Custom form for Admin model."""
    class Meta:
        model = Admin
        fields = '__all__'

class EnseignantAdminForm(forms.ModelForm):
    """Custom form for Enseignant model."""
    class Meta:
        model = Enseignant
        fields = '__all__'

class EtudiantAdminForm(forms.ModelForm):
    """Custom form for Etudiant model."""
    class Meta:
        model = Etudiant
        fields = '__all__'

class MatiereAdminForm(forms.ModelForm):
    """Custom form for Matiere model to override initial values."""
    class Meta:
        model = Matiere
        fields = '__all__'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not self.instance.pk:
            self.initial['course_code'] = ''  # Assuming 'course_code' has a default; adjust as needed

class MatiereCommuneAdminForm(forms.ModelForm):
    """Custom form for MatiereCommune model to override initial values."""
    class Meta:
        model = MatiereCommune
        fields = '__all__'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not self.instance.pk:
            self.initial['course_code'] = ''  # Assuming 'course_code' has a default; adjust as needed

class NoteAdminForm(forms.ModelForm):
    """Custom form for Note model."""
    class Meta:
        model = Note
        fields = '__all__'

class ProfileEnseignantAdminForm(forms.ModelForm):
    """Custom form for ProfileEnseignant model."""
    class Meta:
        model = ProfileEnseignant
        fields = '__all__'

class ProfileEtudiantAdminForm(forms.ModelForm):
    """Custom form for ProfileEtudiant model."""
    class Meta:
        model = ProfileEtudiant
        fields = '__all__'

# Forms for Models without Custom Admin Classes (Minimal Customization)
class AnneeForm(forms.ModelForm):
    class Meta:
        model = Annee
        fields = '__all__'

class FiliereForm(forms.ModelForm):
    class Meta:
        model = Filiere
        fields = '__all__'

class NiveauForm(forms.ModelForm):
    class Meta:
        model = Niveau
        fields = '__all__'

class SemestreForm(forms.ModelForm):
    class Meta:
        model = Semestre
        fields = '__all__'

class EnseignantAnneeForm(forms.ModelForm):
    class Meta:
        model = EnseignantAnnee
        fields = '__all__'

class EtudiantAnneeForm(forms.ModelForm):
    class Meta:
        model = EtudiantAnnee
        fields = '__all__'

class MatiereEtudiantForm(forms.ModelForm):
    class Meta:
        model = MatiereEtudiant
        fields = '__all__'

class MatiereCommuneEtudiantForm(forms.ModelForm):
    class Meta:
        model = MatiereCommuneEtudiant
        fields = '__all__'

# New forms for user interactions


class DefaultSignUpForm(UserCreationForm):
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name', 'phone_number']

class InvitedSignUpForm(UserCreationForm):
    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'phone_number']

class InviteUserForm(forms.Form):
    email = forms.EmailField(label="Email Address")
    role = forms.ChoiceField(label="Role")

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        if user:
            if hasattr(User, 'ROLE_CHOICES'):
                if user.role == 'superadmin':
                    self.fields['role'].choices = User.ROLE_CHOICES
                elif user.role == 'admin':
                    self.fields['role'].choices = [
                        ('admin', 'Admin'),
                        ('enseignant', 'Enseignant')
                    ]
            else:
                self.fields['role'].choices = [
                    ('etudiant', 'Etudiant'),
                    ('enseignant', 'Enseignant'),
                    ('admin', 'Admin'),
                    ('superadmin', 'Superadmin')
                ]