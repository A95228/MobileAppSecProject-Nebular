"""
Kensa's User module.
~~~~~~~~~~~~~~~~~~~~
"""

import os
import pdb

from django.contrib.auth.hashers import PBKDF2PasswordHasher
from django.contrib.auth.models import (
  AbstractBaseUser,
  BaseUserManager,
  PermissionsMixin,
)

from django.db import models
from django.core.exceptions import ValidationError
from django.utils import timezone

from users.kensa_hashers import KensaApiKeyHasher
from users.validators import (
	validate_password,
	validate_not_taken_email,
	validate_username
)


KENSA_HASHER = KensaApiKeyHasher()


class UserManager(BaseUserManager):

	def _create_user(
		self, 
		email, 
		password, 
		is_staff, 
		is_superuser, 
		is_admin, 
		**extra_fields
	):
		if not email: 
			raise ValueError('Users must have an email address')

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
			email,
			password,
			False,
			False,
			False, 
			**extra_fields
		)


	def create_superuser(self, email, password, **extra_fields):
		user=self._create_user(
			email, 
			password, 
			True, 
			True, 
			True, 
			**extra_fields
		)
		user.save(using=self._db)
		return user


	def create_admin(self, email, password, **extra_fields):
		user=self._create_user(
			email, 
			password, 
			False, 
			True, 
			True,
			**extra_fields
		)
		user.save(using=self._db)
		return user


class User(AbstractBaseUser, PermissionsMixin):

	api_key = models.CharField(max_length=254, unique=True) # unsure if editable=True.
	email = models.EmailField(max_length=254, unique=True)
	name = models.CharField(max_length=254, null=True, blank=True)
	username = models.CharField(max_length=254, null=True, blank=True, unique=True)
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

	USERNAME_FIELD = 'email'
	EMAIL_FIELD = 'email'
	REQUIRED_FIELDS = ['organization']

	objects = UserManager()

	def get_short_name(self):
		return self.short_name

	def get_full_name(self):
		return self.name

	def get_absolute_url(self):
		return "/users/%i/" % (self.pk)


	def save(self, *args, **kwargs):
		"""Override save to inject api_key into model."""
		# no reason why email and date joined are not here.
		key = "{0}{1}".format(self.email, str(self.date_joined))
		self.api_key = KENSA_HASHER.encode(key)
		super().save(*args, **kwargs)


	@classmethod
	def _verify_api_key(cls, key, user_api_key) -> bool:
		"""Verify an api_key, for interal use only"""
		return KENSA_HASHER.verify(key, user_api_key)


	@classmethod
	def update_password(cls, password, pk) -> tuple:
		"""Validates a password before commiting changes to database."""
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
	def update_email(cls, email, pk) -> tuple:
		"""Update the email of user with the corresponding pk implement
		email validators before commiting to db."""
		try:
			validate_not_taken_email(email)
		except ValidationError as error:
			return False, error.message

		try:
			user = cls.objects.get(pk=pk)
		except:
			return False, "Unable to update email."
		
		user.email = email
		user.save()

		return True, "Alright, email updated!"


	@classmethod
	def update_first_name(cls, first_name):

		pass


	@classmethod
	def update_last_name(cls, last_name):
		pass


	@classmethod
	def update_short_name(cls, short_name):
		pass

	
	@classmethod
	def get_org_and_id(cls, request, pk):
		"""For db interaction in new scans."""

		if not request.user.is_authenticated:
			return False, "Not authenticated."

		if request.user.organization is None:
			return False, "Missing organization."
		
		org = request.user.org

		return True, (org, pk)


	def __str__(self):
		return "Kensa user | Email: %s." % self.email



