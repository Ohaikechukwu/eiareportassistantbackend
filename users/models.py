from django.utils import timezone
import uuid
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _







class CustomUser(AbstractUser):
    """Custom User model with UUID and email login"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(_('email address'), unique=True)
    first_name = models.CharField(_('first name'), max_length=150, blank=False)
    last_name = models.CharField(_('last name'), max_length=150, blank=False)
    other_name = models.CharField(max_length=100, blank=True, null=True)
    phone = models.CharField(max_length=20)
    department = models.CharField(max_length=100)
    division = models.CharField(max_length=100, blank=True, null=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)


    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name', 'password', 'phone', 'department']

    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.email})"