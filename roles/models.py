from django.db import models
from django.contrib.auth.models import AbstractUser
import uuid
from django.utils import timezone

class User(AbstractUser):
    is_superadmin = models.BooleanField(default=False)

class SuperadminInvitation(models.Model):
    inviter = models.ForeignKey(User, on_delete=models.CASCADE, related_name='invitations_sent')
    recipient_name = models.CharField(max_length=100)
    token = models.UUIDField(default=uuid.uuid4, unique=True)
    pin = models.CharField(max_length=6)  # 6-digit PIN
    pin_attempts = models.IntegerField(default=0)  # Track PIN attempts
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    pin_attempts = models.IntegerField(default=0)

    def is_expired(self):
        return timezone.now() > self.expires_at

    def save(self, *args, **kwargs):
        if not self.pk:  # Only on creation
            self.expires_at = timezone.now() + timezone.timedelta(hours=24)  # 24-hour expiry
            import random
            self.pin = ''.join([str(random.randint(0, 9)) for _ in range(6)])  # Random 6-digit PIN
        super().save(*args, **kwargs)