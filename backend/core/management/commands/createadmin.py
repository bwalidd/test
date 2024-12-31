from django.core.management.base import BaseCommand
from django.conf import settings
from django.contrib.auth import get_user_model
import os

class Command(BaseCommand):
    help = 'Create a superuser if it does not exist'

    def handle(self, *args, **kwargs):
        User = get_user_model()  # Use the custom user model
        superuser_email = os.getenv('DJANGO_SUPERUSER_EMAIL')
        superuser_login = os.getenv('DJANGO_SUPERUSER_LOGIN')
        superuser_password = os.getenv('DJANGO_SUPERUSER_PASSWORD')

        # Ensure all required environment variables are provided
        if not all([superuser_email, superuser_login, superuser_password]):
            self.stderr.write(
                self.style.ERROR("Environment variables for superuser are not properly set.")
            )
            return

        # Check existence using email (or `login` if preferred)
        if not User.objects.filter(email=superuser_email).exists():
            User.objects.create_superuser(
                email=superuser_email,
                login=superuser_login,
                password=superuser_password
            )
            self.stdout.write(self.style.SUCCESS("Superuser created successfully"))
        else:
            self.stdout.write(self.style.SUCCESS("Superuser already exists"))
