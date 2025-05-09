# myapp/management/commands/populate_years.py

from django.core.management.base import BaseCommand
from django.utils import timezone
from roles.models import Annee

class Command(BaseCommand):
    help = 'Pre-populate academic years'

    def add_arguments(self, parser):
        parser.add_argument('--start', type=int, help='Start year (e.g., 2024)')
        parser.add_argument('--count', type=int, default=5, help='Number of academic years to generate')

    def handle(self, *args, **options):
        start_year = options['start'] if options['start'] else timezone.now().year
        count = options['count']

        for i in range(count):
            year_str = f"{start_year + i}-{start_year + i + 1}"
            Annee.objects.get_or_create(annee=year_str)

        self.stdout.write(self.style.SUCCESS(f'{count} academic years starting from {start_year} populated'))
