import pytest
from django import forms
from django.core.exceptions import ValidationError
from .forms import (
    UserAdminForm, InvitationAdminForm, AdminAdminForm, EnseignantAdminForm,
    EtudiantAdminForm, MatiereAdminForm, MatiereCommuneAdminForm, NoteAdminForm,
    ProfileEnseignantAdminForm, ProfileEtudiantAdminForm, AnneeForm, FiliereForm,
    NiveauForm, SemestreForm, EnseignantAnneeForm, EtudiantAnneeForm,
    MatiereEtudiantForm, MatiereCommuneEtudiantForm, DefaultSignUpForm,
    PinForm, ResendActivationForm, InvitationForm
)
from .models import (
    User, Invitation, Admin, Enseignant, Etudiant, Matiere, MatiereCommune,
    Note, ProfileEnseignant, ProfileEtudiant, Annee, Filiere, Niveau, Semestre,
    EnseignantAnnee, EtudiantAnnee, MatiereEtudiant, MatiereCommuneEtudiant
)

# Fixtures
@pytest.fixture
def user_instance():
    return User.objects.create(username='testuser', email='test@example.com', phone_number='1234567890')

@pytest.fixture
def invitation_instance():
    return Invitation.objects.create(role='enseignant', email='teacher@example.com')

# Test Classes for Model Forms with Custom Initial Values
@pytest.mark.django_db
class TestUserAdminForm:
    def test_initial_values(self):
        form = UserAdminForm()
        assert form.initial.get('phone_number') == '', "Phone number initial value should be empty for new instances"
        user = User.objects.create(phone_number='1234567890')
        form = UserAdminForm(instance=user)
        assert form.initial['phone_number'] == '1234567890', "Phone number should match instance value"

    def test_fields_present(self):
        form = UserAdminForm()
        expected_fields = ['username', 'email', 'first_name', 'last_name', 'phone_number']
        for field in expected_fields:
            assert field in form.fields, f"Field {field} should be present in UserAdminForm"

    def test_form_submission(self):
        data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'first_name': 'New',
            'last_name': 'User',
            'phone_number': '9876543210'
        }
        form = UserAdminForm(data=data)
        assert form.is_valid(), "Form should be valid with correct data"
        user = form.save()
        assert user.phone_number == '9876543210', "Saved user should have the provided phone number"

@pytest.mark.django_db
class TestInvitationAdminForm:
    def test_initial_values(self):
        form = InvitationAdminForm()
        assert form.initial.get('pin') == '', "Pin initial value should be empty for new instances"
        invitation = Invitation.objects.create(pin='123456')
        form = InvitationAdminForm(instance=invitation)
        assert form.initial['pin'] == '123456', "Pin should match instance value"

    def test_fields_present(self):
        form = InvitationAdminForm()
        expected_fields = ['role', 'email', 'pin']
        for field in expected_fields:
            assert field in form.fields, f"Field {field} should be present in InvitationAdminForm"

# Test Classes for Standard Model Forms
@pytest.mark.django_db
class TestAdminAdminForm:
    def test_fields_present(self):
        form = AdminAdminForm()
        expected_fields = ['user']
        for field in expected_fields:
            assert field in form.fields, f"Field {field} should be present in AdminAdminForm"

    def test_form_submission(self):
        user = User.objects.create(username='adminuser')
        data = {'user': user.id}
        form = AdminAdminForm(data=data)
        assert form.is_valid(), "Form should be valid with correct data"
        admin = form.save()
        assert admin.user == user, "Saved admin should have the correct user"

@pytest.mark.django_db
class TestEnseignantAdminForm:
    def test_fields_present(self):
        form = EnseignantAdminForm()
        expected_fields = ['user']
        for field in expected_fields:
            assert field in form.fields, f"Field {field} should be present in EnseignantAdminForm"

    def test_form_submission(self):
        user = User.objects.create(username='teacher')
        data = {'user': user.id}
        form = EnseignantAdminForm(data=data)
        assert form.is_valid(), "Form should be valid with correct data"
        enseignant = form.save()
        assert enseignant.user == user, "Saved enseignant should have the correct user"

@pytest.mark.django_db
class TestEtudiantAdminForm:
    def test_fields_present(self):
        form = EtudiantAdminForm()
        expected_fields = ['user']
        for field in expected_fields:
            assert field in form.fields, f"Field {field} should be present in EtudiantAdminForm"

@pytest.mark.django_db
class TestMatiereAdminForm:
    def test_fields_present(self):
        form = MatiereAdminForm()
        expected_fields = ['name']
        for field in expected_fields:
            assert field in form.fields, f"Field {field} should be present in MatiereAdminForm"

@pytest.mark.django_db
class TestMatiereCommuneAdminForm:
    def test_fields_present(self):
        form = MatiereCommuneAdminForm()
        expected_fields = ['name']
        for field in expected_fields:
            assert field in form.fields, f"Field {field} should be present in MatiereCommuneAdminForm"

@pytest.mark.django_db
class TestNoteAdminForm:
    def test_fields_present(self):
        form = NoteAdminForm()
        expected_fields = ['value']
        for field in expected_fields:
            assert field in form.fields, f"Field {field} should be present in NoteAdminForm"

@pytest.mark.django_db
class TestProfileEnseignantAdminForm:
    def test_fields_present(self):
        form = ProfileEnseignantAdminForm()
        expected_fields = ['enseignant']
        for field in expected_fields:
            assert field in form.fields, f"Field {field} should be present in ProfileEnseignantAdminForm"

@pytest.mark.django_db
class TestProfileEtudiantAdminForm:
    def test_fields_present(self):
        form = ProfileEtudiantAdminForm()
        expected_fields = ['etudiant']
        for field in expected_fields:
            assert field in form.fields, f"Field {field} should be present in ProfileEtudiantAdminForm"

@pytest.mark.django_db
class TestAnneeForm:
    def test_fields_present(self):
        form = AnneeForm()
        expected_fields = ['year']
        for field in expected_fields:
            assert field in form.fields, f"Field {field} should be present in AnneeForm"

@pytest.mark.django_db
class TestFiliereForm:
    def test_fields_present(self):
        form = FiliereForm()
        expected_fields = ['name']
        for field in expected_fields:
            assert field in form.fields, f"Field {field} should be present in FiliereForm"

@pytest.mark.django_db
class TestNiveauForm:
    def test_fields_present(self):
        form = NiveauForm()
        expected_fields = ['level']
        for field in expected_fields:
            assert field in form.fields, f"Field {field} should be present in NiveauForm"

@pytest.mark.django_db
class TestSemestreForm:
    def test_fields_present(self):
        form = SemestreForm()
        expected_fields = ['number']
        for field in expected_fields:
            assert field in form.fields, f"Field {field} should be present in SemestreForm"

@pytest.mark.django_db
class TestEnseignantAnneeForm:
    def test_fields_present(self):
        form = EnseignantAnneeForm()
        expected_fields = ['enseignant', 'annee']
        for field in expected_fields:
            assert field in form.fields, f"Field {field} should be present in EnseignantAnneeForm"

@pytest.mark.django_db
class TestEtudiantAnneeForm:
    def test_fields_present(self):
        form = EtudiantAnneeForm()
        expected_fields = ['etudiant', 'annee']
        for field in expected_fields:
            assert field in form.fields, f"Field {field} should be present in EtudiantAnneeForm"

@pytest.mark.django_db
class TestMatiereEtudiantForm:
    def test_fields_present(self):
        form = MatiereEtudiantForm()
        expected_fields = ['matiere', 'etudiant']
        for field in expected_fields:
            assert field in form.fields, f"Field {field} should be present in MatiereEtudiantForm"

@pytest.mark.django_db
class TestMatiereCommuneEtudiantForm:
    def test_fields_present(self):
        form = MatiereCommuneEtudiantForm()
        expected_fields = ['matiere_commune', 'etudiant']
        for field in expected_fields:
            assert field in form.fields, f"Field {field} should be present in MatiereCommuneEtudiantForm"

# Test Classes for Custom Forms
@pytest.mark.django_db
class TestDefaultSignUpForm:
    def test_field_validations(self):
        valid_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'first_name': 'Test',
            'last_name': 'User',
            'phone_number': '1234567890',
            'password1': 'password123',
            'password2': 'password123'
        }
        form = DefaultSignUpForm(data=valid_data)
        assert form.is_valid(), "Form should be valid with correct data"
        invalid_data = valid_data.copy()
        invalid_data['phone_number'] = 'abc'
        form = DefaultSignUpForm(data=invalid_data)
        assert not form.is_valid(), "Form should be invalid with non-digit phone number"
        assert 'phone_number' in form.errors, "Error should be raised for phone_number"

    def test_widget_attributes(self):
        form = DefaultSignUpForm()
        assert isinstance(form.fields['username'].widget, forms.TextInput), "Username should use TextInput widget"
        assert form.fields['username'].widget.attrs['class'] == 'form-control', "Username widget should have class 'form-control'"

    def test_password_matching(self):
        data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'first_name': 'Test',
            'last_name': 'User',
            'phone_number': '1234567890',
            'password1': 'password123',
            'password2': 'different'
        }
        form = DefaultSignUpForm(data=data)
        assert not form.is_valid(), "Form should be invalid if passwords don't match"
        assert 'password2' in form.errors, "Error should be raised for password2"

    def test_form_save(self):
        data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'first_name': 'New',
            'last_name': 'User',
            'phone_number': '1234567890',
            'password1': 'password123',
            'password2': 'password123'
        }
        form = DefaultSignUpForm(data=data)
        assert form.is_valid(), "Form should be valid with correct data"
        user = form.save()
        assert user.check_password('password123'), "Saved user should have the correct password"

@pytest.mark.django_db
class TestPinForm:
    def test_pin_validation(self):
        form = PinForm(data={'pin': '123456'})
        assert form.is_valid(), "Form should be valid with a 6-digit PIN"
        form = PinForm(data={'pin': '12345'})
        assert not form.is_valid(), "Form should be invalid with a PIN shorter than 6 digits"
        form = PinForm(data={'pin': 'abcdef'})
        assert not form.is_valid(), "Form should be invalid with non-digit PIN"

@pytest.mark.django_db
class TestResendActivationForm:
    def test_email_validation(self):
        form = ResendActivationForm(data={'email': 'test@example.com'})
        assert form.is_valid(), "Form should be valid with a correct email"
        form = ResendActivationForm(data={'email': 'invalid'})
        assert not form.is_valid(), "Form should be invalid with an incorrect email"
        assert 'email' in form.errors, "Error should be raised for email"

    def test_widget_attributes(self):
        form = ResendActivationForm()
        assert isinstance(form.fields['email'].widget, forms.EmailInput), "Email should use EmailInput widget"
        assert form.fields['email'].widget.attrs['class'] == 'form-control', "Email widget should have class 'form-control'"

@pytest.mark.django_db
class TestInvitationForm:
    def test_fields_present(self):
        form = InvitationForm()
        expected_fields = ['role', 'email']
        for field in expected_fields:
            assert field in form.fields, f"Field {field} should be present in InvitationForm"

    def test_clean_role(self):
        form = InvitationForm(data={'role': 'enseignant', 'email': 'test@example.com'})
        assert form.is_valid(), "Form should be valid with role 'enseignant'"
        form = InvitationForm(data={'role': 'etudiant', 'email': 'test@example.com'})
        assert not form.is_valid(), "Form should be invalid with role 'etudiant'"
        assert 'role' in form.errors, "Error should be raised for role"

    def test_widget_attributes(self):
        form = InvitationForm()
        assert isinstance(form.fields['role'].widget, forms.Select), "Role should use Select widget"
        assert form.fields['role'].widget.attrs['class'] == 'form-control', "Role widget should have class 'form-control'"