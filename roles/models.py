from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from datetime import timedelta
from django.core.exceptions import ValidationError

class User(AbstractUser):
    ROLE_CHOICES = [
        ('student', 'Student'),
        ('teacher', 'Teacher'),
        ('admin', 'Admin'),
        ('superadmin', 'Superadmin'),
    ]
    
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    phone_number = models.CharField(max_length=15, default='0000000000')
    email = models.EmailField(unique=True)
    
    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.role})"
    
    def get_redirect_url(self):
        if self.role == 'student':
            return '/student/dashboard/'
        elif self.role == 'teacher':
            return '/teacher/dashboard/'
        elif self.role == 'admin':
            return '/admin/panel/'
        elif self.role == 'superadmin':
            return '/superadmin/panel/'
        else:
            return '/role-not-found/'

class Invitation(models.Model):
    role = models.CharField(max_length=20, choices=User.ROLE_CHOICES)
    pin = models.CharField(max_length=10, unique=True)
    inviter = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_invitations')
    invitee_email = models.EmailField()
    status = models.CharField(max_length=20, default='pending')
    accepted_by = models.OneToOneField(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='invitation'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    
    def __str__(self):
        return f"Invitation for {self.role} to {self.invitee_email} by {self.inviter}"
    
    def is_expired(self):
        """Returns True if the invitation has expired, False otherwise."""
        return timezone.now() > self.expires_at
    
    def save(self, *args, **kwargs):
        if self.pk is None:  # Only check when creating a new invitation
            if self.inviter.role not in ['superadmin', 'admin']:
                raise ValidationError("Only superadmins and admins can send invitations.")
            if self.inviter.role == 'admin' and self.role != 'admin':
                raise ValidationError("Admins can only invite users to become admins.")
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=1)
        super().save(*args, **kwargs)