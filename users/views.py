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
from django.contrib import messages
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
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.generics import CreateAPIView, RetrieveUpdateDestroyAPIView

from Kensa.views.api.rest_api import make_api_response
from Kensa.views.helpers import request_method
from users.models import User


logger = logging.getLogger(__name__)


BACKENDS = {
    "allauth" : "allauth.account.auth_backends.AuthenticationBackend",
    "django" : "django.contrib.auth.backends.ModelBackend"
}


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


@request_method(["POST"])
def api_log_in(request): # not tested !
    """Authenticate a user"""
    if request.POST.get("email") is None:
        return make_api_response(
            {"error" : "missing email"}, 400)
    if request.POST.get("password") is None:
        return make_api_response(
            {"error" : "missing password"}, 400)
    try:
        user = authenticate(request.POST["email"], request.POST["password"])
    except PermissionDenied:
        return make_api_response(
            {"error" : "invalid credentials"}, 400)
    if user is None:
        return make_api_response({"error" : "invalid credentials"}, 403)
    if not user.is_active:
        return make_api_response(
            {"error" : "Please contact support to reopen your account"}, 403)

    login(request, user, backend=BACKENDS["django"])
    #Flash welcome message to user in frontend.
    messages.success(request, "Welcome back %s" % request.user.username)
    return HttpResponseRedirect(reverse("home"))
    

@request_method(["GET"])
def api_logout(request):
    if request.user.is_authenticated:
        username = request.user.username 
        logout(request)
        messages.success(request, message="See you later %s !" % username)
        return HttpResponseRedirect(reverse("home"))
    else:
        messages.info(request, message="You can't logout if you are not signed in.")
        return HttpResponseRedirect(reverse("home"))


@request_method(["POST"])
@login_required
@csrf_exempt # for testing, remove for production
def api_edit_password(request):
    """Edit user password"""
    if not request.GET.get("password1") or not request.GET.get("password2"):
        return make_api_response({"error" : "Missing password data"}, 400)

    if request.GET["password1"] != request.GET["password2"]:
        return make_api_response({"error" : "Password must match"}, 400)

    ok, drop = User.update_password(
        request.GET["password1"], request.user.pk)

    if not ok:
        return make_api_response({"error" : drop})

    logout(request) # pop the user out of the session

    return make_api_response({"success" : drop}, 200)


@request_method(["POST"])
def api_edit_email(request):
    return make_api_response({}, 404)


@request_method(["POST"])
def api_edit_username(request):

    return make_api_response({}, 404)


@request_method(["POST"])
def api_edit_image(request):
    return make_api_response({}, 404)


@request_method(["POST"])
def api_edit_name(request):
    return make_api_response({}, 404)


@request_method(["POST"])
def api_edit_first_name(request):
    return make_api_response({}, 404)


@request_method(["POST"])
def api_edit_last_name(request):
    return make_api_response({}, 404)


@request_method(["POST"])
def api_edit_short_name(request):
    return make_api_response({}, 404)



api_user_urls = [
    url(r"^api/v1/api_login", api_log_in),
    url(r"^api/v1/api_logout", api_logout),
    url(r"^api/v1/edit_email$", api_edit_email),
    url(r"^api/v1/edit_password$", api_edit_password),
    url(r"^api/v1/edit_username$", api_edit_username),
    url(r"^api/v1/edit_image$", api_edit_image),
    url(r"^api/v1/edit_name$", api_edit_name),
    url(r"^api/v1/edit_first_name$", api_edit_first_name),
    url(r"^api/v1/edit_last_name$", api_edit_last_name),
    url(r"^api/v1/edit_short_name$", api_edit_short_name),
]