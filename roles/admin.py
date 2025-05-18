from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import (
    User, Invitation, Annee, Filiere, Niveau, Semestre, Admin, Enseignant, Etudiant,
    Matiere, MatiereCommune, Note, EnseignantAnnee, EtudiantAnnee, MatiereEtudiant,
    MatiereCommuneEtudiant, ProfileEnseignant, ProfileEtudiant
)
from .forms import (
    UserAdminForm, InvitationAdminForm, AdminAdminForm, EnseignantAdminForm, EtudiantAdminForm,
    MatiereAdminForm, MatiereCommuneAdminForm, NoteAdminForm, ProfileEnseignantAdminForm,
    ProfileEtudiantAdminForm, AnneeForm, FiliereForm, NiveauForm, SemestreForm,
    EnseignantAnneeForm, EtudiantAnneeForm, MatiereEtudiantForm, MatiereCommuneEtudiantForm
)

# Custom Admin Classes

## User Model (Custom UserAdmin)
@admin.register(User)
class UserAdmin(BaseUserAdmin):
    form = UserAdminForm  # Link custom form
    list_display = ('username', 'email', 'role', 'first_name', 'last_name', 'is_staff')
    search_fields = ('username', 'email', 'first_name', 'last_name')
    list_filter = ('role', 'is_staff', 'is_superuser')
    
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'email', 'role')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2', 'role'),
        }),
    )

## Invitation Model
@admin.register(Invitation)
class InvitationAdmin(admin.ModelAdmin):
    list_display = ['role', 'token', 'email', 'status']  # Adjusted to use 'email'

## Admin Model
@admin.register(Admin)
class AdminAdmin(admin.ModelAdmin):
    form = AdminAdminForm  # Link custom form
    list_display = ('user', 'date_creation')
    search_fields = ('user__username', 'user__email')

## Enseignant Model
@admin.register(Enseignant)
class EnseignantAdmin(admin.ModelAdmin):
    form = EnseignantAdminForm  # Link custom form
    list_display = ('user', 'date_creation')
    search_fields = ('user__username', 'user__email')

## Etudiant Model
@admin.register(Etudiant)
class EtudiantAdmin(admin.ModelAdmin):
    form = EtudiantAdminForm  # Link custom form
    list_display = ('user', 'filiere', 'niveau', 'date_creation')
    search_fields = ('user__username', 'user__email')
    list_filter = ('filiere', 'niveau')

## Matiere Model
@admin.register(Matiere)
class MatiereAdmin(admin.ModelAdmin):
    form = MatiereAdminForm  # Link custom form
    list_display = ('nom_matiere', 'course_code', 'filiere', 'semestre', 'niveau')
    search_fields = ('nom_matiere', 'course_code')
    list_filter = ('filiere', 'semestre', 'niveau')

## MatiereCommune Model
@admin.register(MatiereCommune)
class MatiereCommuneAdmin(admin.ModelAdmin):
    form = MatiereCommuneAdminForm  # Link custom form
    list_display = ('nom_matiere_commune', 'course_code', 'filiere', 'semestre', 'niveau')
    search_fields = ('nom_matiere_commune', 'course_code')
    list_filter = ('filiere', 'semestre', 'niveau')

## Note Model
@admin.register(Note)
class NoteAdmin(admin.ModelAdmin):
    form = NoteAdminForm  # Link custom form
    list_display = ('etudiant', 'matiere', 'matiere_commune', 'cc_note', 'normal_note', 'note_final', 'annee')
    search_fields = ('etudiant__user__username', 'matiere__nom_matiere', 'matiere_commune__nom_matiere_commune')
    list_filter = ('annee', 'matiere', 'matiere_commune')

## ProfileEnseignant Model
@admin.register(ProfileEnseignant)
class ProfileEnseignantAdmin(admin.ModelAdmin):
    form = ProfileEnseignantAdminForm  # Link custom form
    list_display = ('enseignant', 'annee', 'matiere', 'matiere_commune', 'validated', 'date_creation', 'new_entry')
    search_fields = ('enseignant__user__username', 'matiere__nom_matiere', 'matiere_commune__nom_matiere_commune')
    list_filter = ('annee', 'validated', 'new_entry')

## ProfileEtudiant Model
@admin.register(ProfileEtudiant)
class ProfileEtudiantAdmin(admin.ModelAdmin):
    form = ProfileEtudiantAdminForm  # Link custom form
    list_display = ('etudiant', 'filiere', 'semestre', 'annee', 'niveau')
    search_fields = ('etudiant__user__username',)
    list_filter = ('filiere', 'semestre', 'annee', 'niveau')

# Register Models with Minimal Admin Classes
@admin.register(Annee)
class AnneeAdmin(admin.ModelAdmin):
    form = AnneeForm

@admin.register(Filiere)
class FiliereAdmin(admin.ModelAdmin):
    form = FiliereForm

@admin.register(Niveau)
class NiveauAdmin(admin.ModelAdmin):
    form = NiveauForm

@admin.register(Semestre)
class SemestreAdmin(admin.ModelAdmin):
    form = SemestreForm

@admin.register(EnseignantAnnee)
class EnseignantAnneeAdmin(admin.ModelAdmin):
    form = EnseignantAnneeForm

@admin.register(EtudiantAnnee)
class EtudiantAnneeAdmin(admin.ModelAdmin):
    form = EtudiantAnneeForm

@admin.register(MatiereEtudiant)
class MatiereEtudiantAdmin(admin.ModelAdmin):
    form = MatiereEtudiantForm

@admin.register(MatiereCommuneEtudiant)
class MatiereCommuneEtudiantAdmin(admin.ModelAdmin):
    form = MatiereCommuneEtudiantForm