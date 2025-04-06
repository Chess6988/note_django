from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import (
    User, Invitation, Annee, Filiere, Niveau, Semestre, Admin, Enseignant, Etudiant,
    Matiere, MatiereCommune, Note, EnseignantAnnee, EtudiantAnnee, MatiereEtudiant,
    MatiereCommuneEtudiant, ProfileEnseignant, ProfileEtudiant
)

# Custom Admin Classes

## User Model (Custom UserAdmin)
@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ('username', 'email', 'role', 'first_name', 'last_name', 'phone_number', 'is_staff')
    search_fields = ('username', 'email', 'first_name', 'last_name', 'phone_number')
    list_filter = ('role', 'is_staff', 'is_superuser')
    
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'email', 'phone_number', 'role')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2', 'role', 'phone_number'),
        }),
    )

## Invitation Model
@admin.register(Invitation)
class InvitationAdmin(admin.ModelAdmin):
    list_display = ('role', 'pin', 'inviter', 'invitee_email', 'status', 'created_at', 'expires_at')
    search_fields = ('pin', 'invitee_email', 'inviter__username')
    list_filter = ('role', 'status')

## Admin Model
@admin.register(Admin)
class AdminAdmin(admin.ModelAdmin):
    list_display = ('user', 'date_creation')
    search_fields = ('user__username', 'user__email')

## Enseignant Model
@admin.register(Enseignant)
class EnseignantAdmin(admin.ModelAdmin):
    list_display = ('user', 'date_creation')
    search_fields = ('user__username', 'user__email')

## Etudiant Model
@admin.register(Etudiant)
class EtudiantAdmin(admin.ModelAdmin):
    list_display = ('user', 'filiere', 'niveau', 'date_creation')
    search_fields = ('user__username', 'user__email')
    list_filter = ('filiere', 'niveau')

## Matiere Model
@admin.register(Matiere)
class MatiereAdmin(admin.ModelAdmin):
    list_display = ('nom_matiere', 'course_code', 'filiere', 'semestre', 'niveau')
    search_fields = ('nom_matiere', 'course_code')
    list_filter = ('filiere', 'semestre', 'niveau')

## MatiereCommune Model
@admin.register(MatiereCommune)
class MatiereCommuneAdmin(admin.ModelAdmin):
    list_display = ('nom_matiere_commune', 'course_code', 'filiere', 'semestre', 'niveau')
    search_fields = ('nom_matiere_commune', 'course_code')
    list_filter = ('filiere', 'semestre', 'niveau')

## Note Model
@admin.register(Note)
class NoteAdmin(admin.ModelAdmin):
    list_display = ('etudiant', 'matiere', 'matiere_commune', 'cc_note', 'normal_note', 'note_final', 'annee')
    search_fields = ('etudiant__user__username', 'matiere__nom_matiere', 'matiere_commune__nom_matiere_commune')
    list_filter = ('annee', 'matiere', 'matiere_commune')

## ProfileEnseignant Model
@admin.register(ProfileEnseignant)
class ProfileEnseignantAdmin(admin.ModelAdmin):
    list_display = ('enseignant', 'annee', 'matiere', 'matiere_commune', 'validated', 'date_creation', 'new_entry')
    search_fields = ('enseignant__user__username', 'matiere__nom_matiere', 'matiere_commune__nom_matiere_commune')
    list_filter = ('annee', 'validated', 'new_entry')

## ProfileEtudiant Model
@admin.register(ProfileEtudiant)
class ProfileEtudiantAdmin(admin.ModelAdmin):
    list_display = ('etudiant', 'filiere', 'matiere', 'semestre', 'annee', 'niveau', 'matiere_commune')
    search_fields = ('etudiant__user__username', 'matiere__nom_matiere', 'matiere_commune__nom_matiere_commune')
    list_filter = ('filiere', 'semestre', 'annee', 'niveau')

# Register Models without Custom Admin Classes
admin.site.register(Annee)
admin.site.register(Filiere)
admin.site.register(Niveau)
admin.site.register(Semestre)
admin.site.register(EnseignantAnnee)
admin.site.register(EtudiantAnnee)
admin.site.register(MatiereEtudiant)
admin.site.register(MatiereCommuneEtudiant)