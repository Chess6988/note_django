from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.core.validators import RegexValidator
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





class StudentProfileForm(forms.ModelForm):
    """Form for creating or editing a student profile."""
    class Meta:
        model = ProfileEtudiant
        exclude = ['etudiant']
        labels = {
            'annee': 'Academic Year',
            'niveau': 'Level',
            'filiere': 'Field of Study',
            'semestre': 'Semester',
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._set_required_fields()

    def _set_required_fields(self):
        """Set required attributes for form fields."""
        required_fields = ['annee', 'filiere', 'semestre', 'niveau']
        for field in required_fields:
            self.fields[field].required = True

# Forms for User Registration and Activation
class DefaultSignUpForm(UserCreationForm):
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name']
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-control', 'aria-label': 'Username'}),
            'email': forms.EmailInput(attrs={'class': 'form-control', 'aria-label': 'Email'}),
            'first_name': forms.TextInput(attrs={'class': 'form-control', 'aria-label': 'First Name'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control', 'aria-label': 'Last Name'}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['password1'].widget.attrs.update({'class': 'form-control', 'aria-label': 'Password'})
        self.fields['password2'].widget.attrs.update({'class': 'form-control', 'aria-label': 'Confirm Password'})
    
    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get('email')
        first_name = cleaned_data.get('first_name')
        last_name = cleaned_data.get('last_name')
        
        if email and User.objects.filter(email=email).exists():
            self.add_error('email', 'A user with this email already exists.')
        if first_name and last_name and User.objects.filter(first_name=first_name, last_name=last_name).exists():
            self.add_error(None, 'A user with this first and last name already exists.')
        
        return cleaned_data
    
    
class PinForm(forms.Form):
    pin = forms.CharField(
        max_length=6,
        min_length=6,
        validators=[RegexValidator(r'^\d{6}$', "PIN must be a 6-digit number.")],
        widget=forms.TextInput(attrs={'class': 'form-control', 'aria-label': 'PIN'}),
        help_text="Enter the 6-digit PIN sent to you."
    )

class ResendActivationForm(forms.Form):
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={'class': 'form-control', 'aria-label': 'Email'}),
        help_text="Enter your email to resend the activation link."
    )

class InvitationForm(forms.ModelForm):
    class Meta:
        model = Invitation
        fields = ['role', 'email']
        widgets = {
            'role': forms.Select(attrs={'class': 'form-control', 'aria-label': 'Role'}),
            'email': forms.EmailInput(attrs={'class': 'form-control', 'aria-label': 'Email'}),
        }
    
    def clean_role(self):
        role = self.cleaned_data['role']
        if role == 'etudiant':
            raise forms.ValidationError("Cannot invite users as Etudiant.")
        return role