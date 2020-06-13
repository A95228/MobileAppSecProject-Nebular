"""
Kensa's User module.
~~~~~~~~~~~~~~~~~~~~
"""

import os
import pdb

from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)

from django.db import models
from django.core.exceptions import ValidationError
from django.utils import timezone

from users.hasher import KensaApiKeyHasher
from users.validators import (
    validate_email,
    validate_password,
    validate_username,
)


KENSA_HASHER = KensaApiKeyHasher()


class UserManager(BaseUserManager):
    def _create_user(
        self, email, password, is_staff, is_superuser, is_admin, **extra_fields
    ):
        if not email:
            raise ValueError("Users must have an email address")
        now = timezone.now()
        email = self.normalize_email(email)

        user = self.model(
            email=email,
            is_staff=is_staff,
            is_active=True,
            is_superuser=is_superuser,
            is_admin=is_admin,
            last_login=now,
            date_joined=now,
            **extra_fields
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password, **extra_fields):
        return self._create_user(
            email, password, False, False, False, **extra_fields
        )

    def create_superuser(self, email, password, **extra_fields):
        user = self._create_user(
            email, password, True, True, True, **extra_fields
        )
        user.save(using=self._db)
        return user

    def create_admin(self, email, password, **extra_fields):
        user = self._create_user(
            email, password, False, True, True, **extra_fields
        )
        user.save(using=self._db)
        return user


class User(AbstractBaseUser, PermissionsMixin):

    api_key = models.CharField(
        max_length=254, unique=True
    )  # unsure if editable=True.
    email = models.EmailField(max_length=254, unique=True)
    name = models.CharField(max_length=254, null=True, blank=True)
    username = models.CharField(
        max_length=254, null=True, blank=True, unique=True
    )
    organization = models.CharField(max_length=254, null=True, blank=False)
    short_name = models.CharField(max_length=254, null=True, blank=True)
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=150, blank=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    last_login = models.DateTimeField(null=True, blank=True)
    date_joined = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = "email"
    EMAIL_FIELD = "email"
    REQUIRED_FIELDS = ["organization"]

    objects = UserManager()

    def get_short_name(self):
        return self.short_name

    def get_full_name(self):
        return self.name

    def get_absolute_url(self):
        return "/users/%i/" % (self.pk)

    def save(self, *args, **kwargs):  # tested
        """Override save to inject api_key into model."""
        key = "{0}{1}".format(self.email, str(self.date_joined))
        self.api_key = KENSA_HASHER.encode(key)
        super().save(*args, **kwargs)

    @classmethod
    def verify_api_key(cls, key, pk) -> bool:
        """Verify an api_key, for interal use only"""
        try:
            user = cls.objects.get(pk=pk)
        except:
            return False

        if key != user.api_key:
            return False

        return True

    @classmethod
    def update_password(cls, password, pk) -> tuple:  # tested
        """Updates the password if validation passes and user exists."""
        try:
            validate_password(password)
        except ValidationError as issue:
            return False, issue.message

        try:
            user = cls.objects.get(pk=pk)
        except:
            return False, "Unable update password."

        if user.check_password(password):
            return False, "Password can't be the same as actual password."

        user.set_password(password)
        user.save()

        return True, "Success! Log in again with new password."

    @classmethod
    def update_username(cls, username, pk):  # not tested
        """Updates the username if validation passes and user exists"""
        try:
            validate_username(username)
        except ValidationError as error:
            return False, error.message

        try:
            user = cls.objects.get(pk=pk)
        except:
            return False, "unable to update username."

        user.username = username
        user.save()

        return True, "Alright, username updated!"

    @classmethod
    def update_email(cls, email, pk) -> tuple:  # not tested
        """Update the email of user with the corresponding pk implement
		email validators before commiting to db."""
        try:
            validate_email(email)
        except ValidationError as error:
            return False, error.message

        try:
            user = cls.objects.get(pk=pk)
        except:
            return False, "Unable to update email."

        user.email = email
        user.save()

        return True, "Alright, email updated!"

    def __str__(self):
        return "Kensa user | Email: %s." % self.email
