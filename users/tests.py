"""
To run:
    python<version>  manage.py test --verbosity 2 ./users
"""

import os
import re
import pdb
import time
import unittest

from django.core.signing import Signer
from django.db import IntegrityError
from django.test import Client, TestCase
from django.utils.crypto import get_random_string
from django.utils import timezone

from users.hasher import KensaApiKeyHasher
from users.models import User


hasher = KensaApiKeyHasher()


class BaseTest(TestCase):
    """Base class for testing the User and it's functionality"""

    def setUp(self):
        """This runs before each test function"""
        
        self.user_data = dict(
            email="test@regular.com",
            name="Regular User",
            username="",
            password="RegularUser123!",
            organization=1,
            short_name="RU",
            first_name="Regular",
            last_name="User",
        )

        self.admin_data = dict(
            email="test@admin.com",
            name="Admin User",
            username="admin_user",
            password="AdminUser123!",
            organization=1,
            short_name="AU",
            first_name="Admin",
            last_name="User",
        )

        self.super_user_data = dict(
            email="test@sudo.com",
            name="Super User",
            username="super_user",
            password="SuperUser01!",
            organization=1,
            short_name="SU",
            first_name="Super",
            last_name="User",
        )

        self.super_user = User.objects.create_superuser(**self.super_user_data)
        self.admin_user = User.objects.create_admin(**self.admin_data)
        self.user = User.objects.create_user(**self.user_data)
        

    def tearDown(self):
        """Delete the user on each test run"""
        self.super_user.delete()
        self.admin_user.delete()
        self.user.delete()
        



class TestAUserCreation(BaseTest):
    """Test the user creations methods """


    def test_a_banner(self):
        print("\n")
        print("+ " * 25)
        print("\n")
        print("Testing creating all types of users")
        print("\n")
        print("+ " * 25)
        print("\n")
        time.sleep(2)
    
    def test_things_are_create(self):
        """Setup succeded users created"""
        pass

class TestUserApiKeys(BaseTest):
    """Test case for handling api_keys"""


    def test_a_test_banner(self):
        print("\n")
        print("+ " * 25)
        print("\n")
        print("Test User api keys")
        print("\n")
        print("+ " * 25)
        print("\n")
        time.sleep(1.5)


    def test_b_user_api_key_on_registration(self):
        """Test that an api_key is created on registration, 
        given email exists on instance."""
        user_api_key = self.user.api_key
        self.assertIsNotNone(user_api_key)


class TestUserUpdatingPassword(BaseTest):
    """Test the User's updating password functionality."""
    
    def test_a_test_banner(self):
        print("\n")
        print("+ " * 25)
        print("\n")
        print("Fuzz the classmethods that update the user attributes.")
        print("\n")
        print("+ " * 25)
        print("\n")
        time.sleep(1.5)


    def test_b_updating_password_with_current_password(self):
        """Test updating password with current password"""
        
        status, drop = self.user.update_password(
            self.user_data["password"], self.user.pk)
        self.assertFalse(status)
        self.assertEqual(drop, "Password can't be the same as actual password.")
        print("Password cannot be the same as current password. -> Passed")


        drop = self.user.update_password(
            "ChangesPasswordSucces##123", pk=self.user.pk)
        self.assertTrue(drop)
        print("Password updated successfully -> Passed")


        status, drop = self.user.update_password(
            "ChangesPassword##", pk=self.user.pk)
        self.assertFalse(status)
        self.assertEqual(drop, 'Password must include digits.')
        print("Password must include digits -> Passed")


        status, drop = self.user.update_password(
            "ChangesPasswor123", pk=self.user.pk)
        self.assertFalse(status)
        self.assertEqual(drop, 'Password must include special characters.')
        print("Password must include special characters -> Passed")


        status, drop = self.user.update_password(
            "changespassword##123", pk=self.user.pk)
        self.assertFalse(status)
        self.assertEqual(drop, 'Password must include uppercase letters.')
        print("Password must include uppercase letters -> Passed")


        status, drop = self.user.update_password(
            "CHANGESPASSWOR##", pk=self.user.pk)
        self.assertFalse(status)
        self.assertEqual(drop, 'Password must include lowercase letters.')
        print("Password must include lowercase letters -> Passed")


        status, drop = self.user.update_password("CPSu##1", pk=self.user.pk)
        self.assertFalse(status)
        self.assertRegexpMatches(drop, r'Password must be \d+ chars or more.')
        print("Password must be of a certain length -> Passed")


        status, drop = self.user.update_password("ronaldo123", pk=self.user.pk)
        self.assertFalse(status)
        self.assertEqual(drop, 
            'Password is a common password, vulnerable to brute force attacks.')
        print("Password is a common password -> Passed")
