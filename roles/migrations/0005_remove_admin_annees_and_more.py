# Generated by Django 5.0.3 on 2025-04-06 19:30

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('roles', '0004_alter_etudiant_matieres'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='admin',
            name='annees',
        ),
        migrations.AlterUniqueTogether(
            name='adminfiliere',
            unique_together=None,
        ),
        migrations.RemoveField(
            model_name='adminfiliere',
            name='admin',
        ),
        migrations.RemoveField(
            model_name='adminfiliere',
            name='filiere',
        ),
        migrations.RemoveField(
            model_name='admin',
            name='filieres',
        ),
        migrations.AlterUniqueTogether(
            name='adminsemestre',
            unique_together=None,
        ),
        migrations.RemoveField(
            model_name='adminsemestre',
            name='admin',
        ),
        migrations.RemoveField(
            model_name='adminsemestre',
            name='semestre',
        ),
        migrations.RemoveField(
            model_name='admin',
            name='semestres',
        ),
        migrations.AlterUniqueTogether(
            name='enseignantfiliere',
            unique_together=None,
        ),
        migrations.RemoveField(
            model_name='enseignantfiliere',
            name='enseignant',
        ),
        migrations.RemoveField(
            model_name='enseignantfiliere',
            name='filiere',
        ),
        migrations.RemoveField(
            model_name='enseignant',
            name='filieres',
        ),
        migrations.AlterUniqueTogether(
            name='enseignantmatiere',
            unique_together=None,
        ),
        migrations.RemoveField(
            model_name='enseignantmatiere',
            name='enseignant',
        ),
        migrations.RemoveField(
            model_name='enseignantmatiere',
            name='matiere',
        ),
        migrations.RemoveField(
            model_name='enseignant',
            name='matieres',
        ),
        migrations.AlterUniqueTogether(
            name='enseignantmatierecommune',
            unique_together=None,
        ),
        migrations.RemoveField(
            model_name='enseignantmatierecommune',
            name='enseignant',
        ),
        migrations.RemoveField(
            model_name='enseignantmatierecommune',
            name='matiere_commune',
        ),
        migrations.RemoveField(
            model_name='enseignant',
            name='matieres_communes',
        ),
        migrations.AlterUniqueTogether(
            name='enseignantniveau',
            unique_together=None,
        ),
        migrations.RemoveField(
            model_name='enseignantniveau',
            name='enseignant',
        ),
        migrations.RemoveField(
            model_name='enseignantniveau',
            name='niveau',
        ),
        migrations.RemoveField(
            model_name='enseignant',
            name='niveaux',
        ),
        migrations.AlterUniqueTogether(
            name='enseignantsemestre',
            unique_together=None,
        ),
        migrations.RemoveField(
            model_name='enseignantsemestre',
            name='enseignant',
        ),
        migrations.RemoveField(
            model_name='enseignantsemestre',
            name='semestre',
        ),
        migrations.RemoveField(
            model_name='enseignant',
            name='semestres',
        ),
        migrations.AlterUniqueTogether(
            name='etudiantsemestre',
            unique_together=None,
        ),
        migrations.RemoveField(
            model_name='etudiantsemestre',
            name='etudiant',
        ),
        migrations.RemoveField(
            model_name='etudiantsemestre',
            name='semestre',
        ),
        migrations.RemoveField(
            model_name='etudiant',
            name='semestres',
        ),
        migrations.AlterUniqueTogether(
            name='matierecommuneetudiant',
            unique_together=set(),
        ),
        migrations.AlterUniqueTogether(
            name='matiereetudiant',
            unique_together=set(),
        ),
        migrations.RemoveField(
            model_name='enseignant',
            name='annees',
        ),
        migrations.RemoveField(
            model_name='etudiant',
            name='annees',
        ),
        migrations.RemoveField(
            model_name='etudiant',
            name='matieres',
        ),
        migrations.RemoveField(
            model_name='etudiant',
            name='matieres_communes',
        ),
        migrations.AddField(
            model_name='matierecommuneetudiant',
            name='annee',
            field=models.ForeignKey(db_column='id_annee', null=True, on_delete=django.db.models.deletion.CASCADE, to='roles.annee'),
        ),
        migrations.AddField(
            model_name='matiereetudiant',
            name='annee',
            field=models.ForeignKey(db_column='id_annee', null=True, on_delete=django.db.models.deletion.CASCADE, to='roles.annee'),
        ),
        migrations.AlterField(
            model_name='annee',
            name='annee',
            field=models.CharField(max_length=9, null=True),
        ),
        migrations.AlterField(
            model_name='enseignantannee',
            name='annee',
            field=models.ForeignKey(db_column='id_annee', null=True, on_delete=django.db.models.deletion.CASCADE, to='roles.annee'),
        ),
        migrations.AlterField(
            model_name='etudiantannee',
            name='annee',
            field=models.ForeignKey(db_column='id_annee', null=True, on_delete=django.db.models.deletion.CASCADE, to='roles.annee'),
        ),
        migrations.AlterUniqueTogether(
            name='matierecommuneetudiant',
            unique_together={('etudiant', 'matiere_commune', 'annee')},
        ),
        migrations.AlterUniqueTogether(
            name='matiereetudiant',
            unique_together={('etudiant', 'matiere', 'annee')},
        ),
        migrations.CreateModel(
            name='ProfileEnseignant',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('validated', models.BooleanField(default=False)),
                ('date_creation', models.DateTimeField(auto_now_add=True)),
                ('new_entry', models.BooleanField(default=True)),
                ('annee', models.ForeignKey(db_column='id_annee', null=True, on_delete=django.db.models.deletion.CASCADE, to='roles.annee')),
                ('enseignant', models.ForeignKey(db_column='id_enseignant', on_delete=django.db.models.deletion.CASCADE, to='roles.enseignant')),
                ('matiere', models.ForeignKey(db_column='id_matiere', null=True, on_delete=django.db.models.deletion.CASCADE, to='roles.matiere')),
                ('matiere_commune', models.ForeignKey(db_column='id_matiere_commune', null=True, on_delete=django.db.models.deletion.CASCADE, to='roles.matierecommune')),
            ],
            options={
                'db_table': 'profile_enseignant',
            },
        ),
        migrations.CreateModel(
            name='ProfileEtudiant',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('annee', models.ForeignKey(db_column='id_annee', null=True, on_delete=django.db.models.deletion.CASCADE, to='roles.annee')),
                ('etudiant', models.ForeignKey(db_column='id_etudiant', on_delete=django.db.models.deletion.CASCADE, to='roles.etudiant')),
                ('filiere', models.ForeignKey(db_column='id_filiere', on_delete=django.db.models.deletion.CASCADE, to='roles.filiere')),
                ('matiere', models.ForeignKey(db_column='id_matiere', on_delete=django.db.models.deletion.CASCADE, to='roles.matiere')),
                ('matiere_commune', models.ForeignKey(db_column='id_matiere_commune', null=True, on_delete=django.db.models.deletion.CASCADE, to='roles.matierecommune')),
                ('niveau', models.ForeignKey(db_column='id_niveau', on_delete=django.db.models.deletion.CASCADE, to='roles.niveau')),
                ('semestre', models.ForeignKey(db_column='id_semestre', on_delete=django.db.models.deletion.CASCADE, to='roles.semestre')),
            ],
            options={
                'db_table': 'profile_etudiant',
            },
        ),
        migrations.DeleteModel(
            name='AdminAnnee',
        ),
        migrations.DeleteModel(
            name='AdminFiliere',
        ),
        migrations.DeleteModel(
            name='AdminSemestre',
        ),
        migrations.DeleteModel(
            name='EnseignantFiliere',
        ),
        migrations.DeleteModel(
            name='EnseignantMatiere',
        ),
        migrations.DeleteModel(
            name='EnseignantMatiereCommune',
        ),
        migrations.DeleteModel(
            name='EnseignantNiveau',
        ),
        migrations.DeleteModel(
            name='EnseignantSemestre',
        ),
        migrations.DeleteModel(
            name='EtudiantSemestre',
        ),
    ]
