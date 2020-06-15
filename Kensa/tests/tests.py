"""
Test's for Kensa's API
~~~~~~~~~~~~~~~~~~~~~~
"""
import os
import pdb
import re
import logging
import unittest


from django.test import (
    Client,
    TestCase,
    RequestFactory
)
from django.urls import reverse


from users.models import User
from users.tests.test_data import user_data

from Kensa.urls import urlpatterns

from django.conf import settings


class BaseTest(TestCase):


    def setup(self):
        self.test_dir = os.path.join(settings.BASE_DIR, "test_dir")
        self.user = User.create_user(user_data["email"], user_data["password"])
        self.client = Client()
        pdb.set_trace()
        print()


    def tearDown(self):
        pass


class TestApi(BaseTest)

    def test_acces_tokens(self):
        with self.client.

