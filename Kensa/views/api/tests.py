# Test for rest_api_routes and tools

import pdb
import re
import unittest

from django.test import TestCase, Client 
from django.urls import reverse


from users.models import User


class TestAndroidAnalyzerRoutes(TestCase):

    def setUp(self):
        self.test_user = dict(
            email="test@regular.com",
            name="Regular User",
            username="",
            password="RegularUser123!",
            organization=1,
            short_name="RU",
            first_name="Regular",
            last_name="User",
        )
        self.user = User.objects.create_user(**self.test_user)
        self.creds = dict(
            email="test@regular.com",
            password="RegularUser123!"
        )   


    def test_a_access_token(self):
        pass


    def tearDown(self):
        self.user.delete()
