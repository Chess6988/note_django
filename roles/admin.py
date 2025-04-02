from django.contrib import admin
from .models import User, SuperadminInvitation

admin.site.register(User)
admin.site.register(SuperadminInvitation)