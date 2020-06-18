"""
Validator tests
~~~~~~~~~~~~~~~
"""

import pdb
import time

from django.core.exceptions import ValidationError
from django.test import TestCase

from users.models import User
from users.tests.test_data import emails, user_data
from users.validators import (
    validate_api_key,
    validate_email,
    validate_password,
    validate_username,
)

from django.contrib.auth.password_validation import CommonPasswordValidator

usernames = CommonPasswordValidator().passwords


class TestEmailValidator(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            user_data["email"], user_data["password"]
        )

    def test_banner(self):
        print("\n")
        print("+ " * 25)
        print("\n")
        print("Testing email_validator")
        print("\n")
        print("+ " * 25)
        print("\n")
        time.sleep(2)

    def test_email_does_not_exists(self):
        """Test to see if the validator returns True if
        the email does not exists."""
        for email in emails:
            self.assertTrue(validate_email(email))

    def test_email_exists(self):
        """Test to see if the validator raises ValueError 
        if user with email exists"""
        with self.assertRaises(ValidationError):
            validate_email(self.user.email)

    def tearDown(self):
        self.user.delete()


class TestUsernameValidator(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            user_data["email"], user_data["password"]
        )

    def test_username_does_not_exists(self):
        """Test to see if the validator returns True if the email does not exists."""
        for username in usernames:
            self.assertTrue(validate_username(username))

    def test_username_exists(self):
        """Test to see if the validator raises ValueError if user with email exists"""
        with self.assertRaises(ValidationError):
            validate_username(self.user.username)

    def tearDown(self):
        self.user.delete()
