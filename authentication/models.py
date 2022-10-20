from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.base_user import BaseUserManager
from django.utils.translation import gettext_lazy as _
from rest_framework_simplejwt.tokens import RefreshToken

# Create your models here.


class CustomUserManager(BaseUserManager):

    def create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError(_("Email should be provided"))

        email = self.normalize_email(email)
        new_user = self.model(email=email, **extra_fields)

        new_user.set_password(password)
        new_user.save()
        return new_user

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError("Superuser should have is_staff as True")
        if extra_fields.get('is_superuser') is not True:
            raise ValueError("Super user should have is_superuser True")
        if extra_fields.get('is_active') is not True:
            raise ValueError("Superuser should have is_active True")

        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    username = models.CharField(max_length=25, unique=True)
    email = models.EmailField(max_length=80, unique=True)


    objects = CustomUserManager()
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username',]

    def __str__(self):
        return f"<User {self.email}"


    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }



class Profile(models.Model):
    """Creates users profile information"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, null=True, blank=True)
    image = models.ImageField(default='default.jpg', upload_to='profile_pics')
    address = models.CharField(max_length=255, null=True, blank=True,)
    city = models.CharField(max_length=255, null=True, blank=True,)
    country = models.CharField(max_length=255, null=True, blank=True,)
    created_at = models.DateTimeField(auto_now=True)
    last_modified = models.DateTimeField(auto_now=True)
    commission = models.PositiveIntegerField(default=1)
    telephone_Number = models.CharField(max_length=20, null=True, blank=True,)
    email_confirmed = models.BooleanField(default=False)
    organisation_name = models.CharField(default=False, max_length=255)

    def __str__(self):
        return self.address

