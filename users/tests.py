"""
Test for some of the User model functionalities.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Finds:
~~~~~~

User.objects._create_user() Raises a TypeError
When passing date_joined or is_active directly.

user_data = dict(
        email="test@test.com",
        name="Tester Case",
        username="winterfell369",
        password=SIGNER.sign("$$$").split(":"),
        organization=1,
        short_name="san",
        first_name="Tester",
        last_name="Case",
        is_staff=False,
        is_superuser=False,
        is_admin=False,
        date_joined=timezone.now()
)

user = User.objects._create_user(**user_data)

Traceback (most recent call last):
  File "/kensa/users/tests.py", line 42, in test_a_user_creation
    user = User.objects._create_user(**self.user_data)
  File "/kensa/users/models.py", line 39, in _create_user
    **extra_fields
TypeError: ModelBase object got multiple values for keyword argument 'date_joined'
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""

import re
import pdb
import unittest

from django.core.signing import Signer
from django.db import IntegrityError
from django.test import Client, TestCase
from django.utils import timezone
from users.models import User


class Ok(Exception):
    pass


class TestUserFunk(TestCase):
    """
    Fuzz the User.
    """

    def setUp(self):
        """This runs before each test function"""
        self.user_data = dict(
            	email="test@test.com",
                name="Tester Case",
                username="zzzzz)*369",
                password="CustomTestPa$word123",
                organization=1,
                short_name="san",
                first_name="Tester",
                last_name="Case",
                is_staff=False,
                is_superuser=False,
                is_admin=False,
        )


    def test_a_user_creation(self):
        """Test that a single regular user is created."""
        user = User.objects._create_user(**self.user_data)
        self.assertEqual(user.pk, 1)


    def test_b_updating_password_with_validators(self): # tested
        """ Test updating password classmethod & pasword validation"""
        user = User.objects._create_user(**self.user_data)
        
        # ==== Validation for new password is the same as previous password ====

        status, drop = user.update_password(self.user_data["password"], user.pk)
        self.assertFalse(status)
        self.assertEqual(drop, "Password can't be the same as actual password.")

        # =========== Validation for validate_password_function =============

        # Success
        drop = user.update_password("ChangesPasswordSucces##123", pk=user.pk)
        self.assertTrue(drop)

        # Fail, must include digits.
        status, drop = user.update_password("ChangesPassword##", pk=user.pk)
        self.assertFalse(status)
        self.assertEqual(drop, 'Password must include digits.')
        
        # Fail must include special chars.
        status, drop = user.update_password("ChangesPasswor123", pk=user.pk)
        self.assertFalse(status)
        self.assertEqual(drop, 'Password must include special characters.')
        
        # Fail must include upper case letters.
        status, drop = user.update_password("changespassword##123", pk=user.pk)
        self.assertFalse(status)
        self.assertEqual(drop, 'Password must include uppercase letters.')
        
        # Fail must include lower case letters
        status, drop = user.update_password("CHANGESPASSWOR##", pk=user.pk)
        self.assertFalse(status)
        self.assertEqual(drop, 'Password must include lowercase letters.')
        
        status, drop = user.update_password("CPSu##1", pk=user.pk)
        self.assertFalse(status)
        self.assertRegexpMatches(drop, r'Password must be \d+ chars or more.')

        status, drop = user.update_password("ronaldo123", pk=user.pk)
        self.assertFalse(status)
        self.assertEqual(
            drop, 
            'Password is a common password, vulnerable to brute force attacks.'
        )


    @unittest.expectedFailure
    def test_email_exists(self):
        """ Test creating a regular User with an email that already exists."""
        User.objects._create_user(**self.user_data)
        spoof_data = self.user_data
        self.user_data.update({"username" : "speedy_gonzalez"})
        user = User.objects.create(**spoof_data)
        user.save()


    def tearDown(self):
        """Delete the user on each test run"""
        pass
