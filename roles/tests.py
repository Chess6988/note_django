import pytest
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import (
    User, Invitation, Annee, Filiere, Niveau, Semestre, Admin, Enseignant, Etudiant,
    Matiere, MatiereCommune, Note, EnseignantAnnee, EtudiantAnnee, MatiereEtudiant,
    MatiereCommuneEtudiant, ProfileEnseignant, ProfileEtudiant
)
from .admin import (
    UserAdmin, InvitationAdmin, AdminAdmin, EnseignantAdmin, EtudiantAdmin,
    MatiereAdmin, MatiereCommuneAdmin, NoteAdmin, ProfileEnseignantAdmin,
    ProfileEtudiantAdmin
)

# --- Test Model Registration ---

@pytest.mark.django_db
def test_user_admin_registration():
    """Test that User is registered with UserAdmin."""
    assert admin.site._registry[User].__class__ == UserAdmin

@pytest.mark.django_db
def test_invitation_admin_registration():
    """Test that Invitation is registered with InvitationAdmin."""
    assert admin.site._registry[Invitation].__class__ == InvitationAdmin

@pytest.mark.django_db
def test_admin_model_admin_registration():
    """Test that Admin is registered with AdminAdmin."""
    assert admin.site._registry[Admin].__class__ == AdminAdmin

@pytest.mark.django_db
def test_enseignant_admin_registration():
    """Test that Enseignant is registered with EnseignantAdmin."""
    assert admin.site._registry[Enseignant].__class__ == EnseignantAdmin

@pytest.mark.django_db
def test_etudiant_admin_registration():
    """Test that Etudiant is registered with EtudiantAdmin."""
    assert admin.site._registry[Etudiant].__class__ == EtudiantAdmin

@pytest.mark.django_db
def test_matiere_admin_registration():
    """Test that Matiere is registered with MatiereAdmin."""
    assert admin.site._registry[Matiere].__class__ == MatiereAdmin

@pytest.mark.django_db
def test_matiere_commune_admin_registration():
    """Test that MatiereCommune is registered with MatiereCommuneAdmin."""
    assert admin.site._registry[MatiereCommune].__class__ == MatiereCommuneAdmin

@pytest.mark.django_db
def test_note_admin_registration():
    """Test that Note is registered with NoteAdmin."""
    assert admin.site._registry[Note].__class__ == NoteAdmin

@pytest.mark.django_db
def test_profile_enseignant_admin_registration():
    """Test that ProfileEnseignant is registered with ProfileEnseignantAdmin."""
    assert admin.site._registry[ProfileEnseignant].__class__ == ProfileEnseignantAdmin

@pytest.mark.django_db
def test_profile_etudiant_admin_registration():
    """Test that ProfileEtudiant is registered with ProfileEtudiantAdmin."""
    assert admin.site._registry[ProfileEtudiant].__class__ == ProfileEtudiantAdmin

# Models without custom admin classes
@pytest.mark.django_db
def test_annee_registration():
    """Test that Annee is registered with default ModelAdmin."""
    assert isinstance(admin.site._registry[Annee], admin.ModelAdmin)

@pytest.mark.django_db
def test_filiere_registration():
    """Test that Filiere is registered with default ModelAdmin."""
    assert isinstance(admin.site._registry[Filiere], admin.ModelAdmin)

@pytest.mark.django_db
def test_niveau_registration():
    """Test that Niveau is registered with default ModelAdmin."""
    assert isinstance(admin.site._registry[Niveau], admin.ModelAdmin)

@pytest.mark.django_db
def test_semestre_registration():
    """Test that Semestre is registered with default ModelAdmin."""
    assert isinstance(admin.site._registry[Semestre], admin.ModelAdmin)

@pytest.mark.django_db
def test_enseignant_annee_registration():
    """Test that EnseignantAnnee is registered with default ModelAdmin."""
    assert isinstance(admin.site._registry[EnseignantAnnee], admin.ModelAdmin)

@pytest.mark.django_db
def test_etudiant_annee_registration():
    """Test that EtudiantAnnee is registered with default ModelAdmin."""
    assert isinstance(admin.site._registry[EtudiantAnnee], admin.ModelAdmin)

@pytest.mark.django_db
def test_matiere_etudiant_registration():
    """Test that MatiereEtudiant is registered with default ModelAdmin."""
    assert isinstance(admin.site._registry[MatiereEtudiant], admin.ModelAdmin)

@pytest.mark.django_db
def test_matiere_commune_etudiant_registration():
    """Test that MatiereCommuneEtudiant is registered with default ModelAdmin."""
    assert isinstance(admin.site._registry[MatiereCommuneEtudiant], admin.ModelAdmin)

# --- Test Custom Admin Class Attributes ---

def test_user_admin_attributes():
    """Test attributes of UserAdmin."""
    admin_instance = UserAdmin(User, admin.site)
    assert admin_instance.list_display == ('username', 'email', 'role', 'first_name', 'last_name', 'phone_number', 'is_staff')
    assert admin_instance.search_fields == ('username', 'email', 'first_name', 'last_name', 'phone_number')
    assert admin_instance.list_filter == ('role', 'is_staff', 'is_superuser')
    assert admin_instance.fieldsets == (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'email', 'phone_number', 'role')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    assert admin_instance.add_fieldsets == (
        (None, {'classes': ('wide',), 'fields': ('username', 'email', 'password1', 'password2', 'role', 'phone_number')}),
    )

def test_invitation_admin_attributes():
    """Test attributes of InvitationAdmin."""
    admin_instance = InvitationAdmin(Invitation, admin.site)
    assert admin_instance.list_display == ('role', 'pin', 'inviter', 'invitee_email', 'status', 'created_at', 'expires_at')
    assert admin_instance.search_fields == ('pin', 'invitee_email', 'inviter__username')
    assert admin_instance.list_filter == ('role', 'status')

def test_admin_admin_attributes():
    """Test attributes of AdminAdmin."""
    admin_instance = AdminAdmin(Admin, admin.site)
    assert admin_instance.list_display == ('user', 'date_creation')
    assert admin_instance.search_fields == ('user__username', 'user__email')

def test_enseignant_admin_attributes():
    """Test attributes of EnseignantAdmin."""
    admin_instance = EnseignantAdmin(Enseignant, admin.site)
    assert admin_instance.list_display == ('user', 'date_creation')
    assert admin_instance.search_fields == ('user__username', 'user__email')

def test_etudiant_admin_attributes():
    """Test attributes of EtudiantAdmin."""
    admin_instance = EtudiantAdmin(Etudiant, admin.site)
    assert admin_instance.list_display == ('user', 'filiere', 'niveau', 'date_creation')
    assert admin_instance.search_fields == ('user__username', 'user__email')
    assert admin_instance.list_filter == ('filiere', 'niveau')

def test_matiere_admin_attributes():
    """Test attributes of MatiereAdmin."""
    admin_instance = MatiereAdmin(Matiere, admin.site)
    assert admin_instance.list_display == ('nom_matiere', 'course_code', 'filiere', 'semestre', 'niveau')
    assert admin_instance.search_fields == ('nom_matiere', 'course_code')
    assert admin_instance.list_filter == ('filiere', 'semestre', 'niveau')

def test_matiere_commune_admin_attributes():
    """Test attributes of MatiereCommuneAdmin."""
    admin_instance = MatiereCommuneAdmin(MatiereCommune, admin.site)
    assert admin_instance.list_display == ('nom_matiere_commune', 'course_code', 'filiere', 'semestre', 'niveau')
    assert admin_instance.search_fields == ('nom_matiere_commune', 'course_code')
    assert admin_instance.list_filter == ('filiere', 'semestre', 'niveau')

def test_note_admin_attributes():
    """Test attributes of NoteAdmin."""
    admin_instance = NoteAdmin(Note, admin.site)
    assert admin_instance.list_display == ('etudiant', 'matiere', 'matiere_commune', 'cc_note', 'normal_note', 'note_final', 'annee')
    assert admin_instance.search_fields == ('etudiant__user__username', 'matiere__nom_matiere', 'matiere_commune__nom_matiere_commune')
    assert admin_instance.list_filter == ('annee', 'matiere', 'matiere_commune')

def test_profile_enseignant_admin_attributes():
    """Test attributes of ProfileEnseignantAdmin."""
    admin_instance = ProfileEnseignantAdmin(ProfileEnseignant, admin.site)
    assert admin_instance.list_display == ('enseignant', 'annee', 'matiere', 'matiere_commune', 'validated', 'date_creation', 'new_entry')
    assert admin_instance.search_fields == ('enseignant__user__username', 'matiere__nom_matiere', 'matiere_commune__nom_matiere_commune')
    assert admin_instance.list_filter == ('annee', 'validated', 'new_entry')

def test_profile_etudiant_admin_attributes():
    """Test attributes of ProfileEtudiantAdmin."""
    admin_instance = ProfileEtudiantAdmin(ProfileEtudiant, admin.site)
    assert admin_instance.list_display == ('etudiant', 'filiere', 'matiere', 'semestre', 'annee', 'niveau', 'matiere_commune')
    assert admin_instance.search_fields == ('etudiant__user__username', 'matiere__nom_matiere', 'matiere_commune__nom_matiere_commune')
    assert admin_instance.list_filter == ('filiere', 'semestre', 'annee', 'niveau')