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

from users.models import User
from users.kensa_hashers import KensaApiKeyHasher



hasher = KensaApiKeyHasher()


class BaseFunk(TestCase):
    """
    Base class for testing
    ~~~~~~~~~~~~~~~~~~~~~~
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
        self.bad_d = self.user_data.copy()
        self.bad_d.update({"username" : "speedy_gonalez"})
        self.user = user = User.objects._create_user(**self.user_data)


    def tearDown(self):
        """Delete the user on each test run"""
        msg = "Deleting test user with pk -> {} email -> {} \n".format(
            self.user.pk, self.user.email)
        print(msg)
        User.objects.get(pk=self.user.pk).delete()



class TestUserCreationFunk(BaseFunk):
    """
    Fuzz the User and test it's creation.
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    """

    def test_a_user_creation(self):
        """Test that a single regular user is created."""
        self.assertTrue(User.objects.get(username=self.user_data["username"]))



class TestUserApiFunk(BaseFunk):


    def test_a_test_banner(self):
        print("\n")
        print("+ " * 25)
        print("\n")
        print("Test creating a kensa user and her api_key")
        print("\n")
        print("+ " * 25)
        print("\n")
        time.sleep(2)


    def test_b_user_api_key_on_registration(self):
        """Test that an api_key is created on registration, 
        given email exists on instance.
        
        Also tests the classmethod to verify the api_key."""

        user_key = self.user.api_key
        xxxpression = (
            self.user._verify_api_key(
                f"{self.user.email}{os.getenv('KENSA_PEPPER', 'x_x')}",
                user_key
                )
            )
        self.assertTrue(xxxpression)



class TestUserUpdatingPasswordFunk(BaseFunk):
    """
    Fuzz the classmethods that update the user attributes.
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    """
    
    def test_a_test_banner(self):
        print("\n")
        print("+ " * 25)
        print("\n")
        print("Fuzz the classmethods that update the user attributes.")
        print("\n")
        print("+ " * 25)
        print("\n")
        time.sleep(2)


    def test_b_updating_password_with_validators(self): # tested
        """ Test updating password classmethod & pasword validation\n"""
        

        status, drop = self.user.update_password(
            self.user_data["password"], self.user.pk)
        self.assertFalse(status)
        self.assertEqual(drop, "Password can't be the same as actual password.")
        print("\nPassword cannot be the same as current password. -> Passed")


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


class TestKensaApiHasherFunk(TestCase):
    """Test Cases for Kensa's api hasher object."""

    def setUp(self):
        """Test Kensa's api key encoder.\n"""
        self.raw_key = "user@user.com"+timezone.now().__str__()
        self.hash = hasher.encode(self.raw_key)
    
    def test_a_test_banner(self):
        print("\n")
        print("+ " * 25)
        print("\n")
        print("Testing kensa api encoder object")
        print("\n")
        print("+ " * 25)
        print("\n")
        time.sleep(2)
        

    def test_verify(self):
        xpresion = hasher.verify(self.raw_key, self.hash) 
        self.assertTrue(xpresion)
    

    def test_z_multiple_encodings_and_verifications(self):
        """Test the hasher with many values"""
        print()
        print("+ " * 25)
        print()
        for _ in range(50):
            key = get_random_string(length=13)
            key_hash = hasher.encode(key)
            key_and_key_hash_check = hasher.verify(key, key_hash)
            self.assertTrue(key_and_key_hash_check)
            print("key : {0} matches hash : {1}".format(key, key_hash))

