"""
This module contains routes for the User API REST functionality
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
TO DO:

* Must add middleware to check if user is authenticated and
  if it has permissions to do the operations within the body
  of the view.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""

import logging
import pdb

from django.db import IntegrityError
from django.conf.urls import url
from django.contrib.auth import (
    authenticate,
    login,
    logout,
    PermissionDenied,
    update_session_auth_hash,
)
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.views.generic import UpdateView
from django.views.decorators.csrf import csrf_exempt

from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.generics import CreateAPIView, RetrieveUpdateDestroyAPIView

from users.models import User


logger = logging.getLogger(__name__)


BACKENDS = {
    "allauth" : "allauth.account.auth_backends.AuthenticationBackend",
    "django" : "django.contrib.auth.backends.ModelBackend"
}

from rest_framework_simplejwt.tokens import RefreshToken


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = (
            'id',
            'email',
            'name',
            'last_name',
            'phone_number',
            'addr_city',
            'addr_state',
            'addr_country',
            'organization'
        )


class ProfileView(CreateAPIView, RetrieveUpdateDestroyAPIView):

    def get(self, request, *args, **kwargs):
        user = User.objects.get(request.user)
        UserSerializer(user)
        return Response(data=UserSerializer(user).data, status=status.HTTP_200_OK)

    def partial_update(self, request, *args, **kwargs):
        return super(ProfileView, self).partial_update(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        user = User.objects.get(request.user)
        try:
            user.name = request.data['first_name']
            user.last_name = request.data['last_name']
            user.phone_number = request.data['phone_number']
            user.addr_city = request.data['addr_city']
            user.addr_state = request.data['addr_state']
            user.addr_country = request.data['addr_country']
            user.organization = request.data['organization']
            user.save()
        except IntegrityError:
            return Response({
                'message': 'Internal Server Error.',
            }, status=status.HTTP_400_BAD_REQUEST)

        return Response(data=UserSerializer(user).data, status=status.HTTP_200_OK)
