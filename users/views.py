# Module contains views for Kensa's User API

from django.conf.urls import url
from django.shortcuts import render
from django.views.generic import UpdateView


from rest_framework import serializers, status
from rest_framework.response import Response
from django.db import IntegrityError
from users.models import User

from Kensa.views.api.rest_api import make_api_response
from Kensa.views.helpers import request_method


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ('id', 'email', 'name', 'last_name', 'phone_number', 'addr_city', 'addr_state', 'addr_country',
                  'organization')


class ProfileView(UpdateView):

    def get(self, request, *args, **kwargs):
        user = User.objects.get(request.user)
        UserSerializer(user)
        return Response(data=UserSerializer(user).data, status=status.HTTP_200_OK)

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

# Turning these to CBV's

@request_method(["POST"])
def api_edit_email(request):
    #if not request.user.is_authenticated:
    #    return make_api_response({"error" : "login and try again"},
    #        status=401)
    #if len(request.user.get_user_permissions()) < 0:
    #    return make_api_response({"error" : "login and try again"},
    #        status=403)
    #if request.POST.get("new_email", None) is None:
    #    error = "New email is required"
    #    return make_api_response({"error" : error}, status=BAD_REQUEST)
    #if request.POST.get("new_email") == request.user.email:
    #    error = "%s can't be the same as current email" % request.POST["email"]
    #    return make_api_response({"error" : error}, 400)
    #
    return make_api_response({}, 404)


@request_method(["POST"])
def api_edit_password(request):
    #if not request.user.is_authenticated:
    #    return make_api_response({"error" : "login and try again"},
    #        status=401)
    #if len(request.user.get_user_permissions()) < 0:
    #    return make_api_response({"error" : "login and try again"},
    #        status=403)
    # check the password does not match the current password
    # check the password does not violate the password requirements e.g -
    # includes !@#$%^&*()_+, longer than 8 etc. . 
    # if there are two password fields, check they match
    # change
    return make_api_response({}, 404)


@request_method(["POST"])
def api_edit_username(request):
    #if not request.user.is_authenticated:
    #    return make_api_response({"error" : "login and try again"},
    #        status=401)
    #if len(request.user.get_user_permissions()) < 0:
    #    return make_api_response({"error" : "login and try again"},
    #        status=403)
    # try to get the username, if the username already exists, show error
    # check username follows protocol,
    # change.
    return make_api_response({}, 404)


@request_method(["POST"])
def api_edit_image(request):
    #if not request.user.is_authenticated:
    #    return make_api_response({"error" : "login and try again"},
    #        status=401)
    #if len(request.user.get_user_permissions()) < 0:
    #    return make_api_response({"error" : "login and try again"},
    #        status=403)
    # check the image is not malicious
    # save the image in the uploads? will this be a cloud service?
    return make_api_response({}, 404)


@request_method(["POST"])
def api_edit_name(request):
    #if not request.user.is_authenticated:
    #    return make_api_response({"error" : "login and try again"},
    #        status=401)
    #if len(request.user.get_user_permissions()) < 0:
    #    return make_api_response({"error" : "login and try again"},
    #        status=403)
    return make_api_response({}, 404)


@request_method(["POST"])
def api_edit_first_name(request):
    #if not request.user.is_authenticated:
    #    return make_api_response({"error" : "login and try again"},
    #        status=401)
    #if len(request.user.get_user_permissions()) < 0:
    #    return make_api_response({"error" : "login and try again"},
    #        status=403)
    return make_api_response({}, 404)


@request_method(["POST"])
def api_edit_last_name(request):
    #if not request.user.is_authenticated:
    #    return make_api_response({"error" : "login and try again"},
    #        status=401)
    #if len(request.user.get_user_permissions()) < 0:
    #    return make_api_response({"error" : "login and try again"},
    #        status=403)
    return make_api_response({}, 404)


@request_method(["POST"])
def api_edit_short_name(request):
    #if not request.user.is_authenticated:
    #    return make_api_response({"error" : "login and try again"},
    #        status=401)
    #if len(request.user.get_user_permissions()) < 0:
    #    return make_api_response({"error" : "login and try again"},
    #        status=403)
    return make_api_response({}, 404)


@request_method(["GET"])
def api_get_user_info(request):
    #if not request.user.is_authenticated:
    #    return make_api_response({"error" : "login and try again"},
    #        status=401)
    #if len(request.user.get_user_permissions()) < 0:
    #    return make_api_response({"error" : "login and try again"},
    #        status=403)
    # more checks here
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # u = request.user
    # info = dict(
    #   email=u.email,
    #   username=u.username,
    #   name=u.name,  
    #   first_name=u.first_name,
    #   last_name=u.last_name,
    #   short_name=u.short_name,
    #   organization=u.organization,
    #   is_active=u.is_active
    # )
    #return make_api_response({"user_info" : info}, status=OK)
    return make_api_response({}, 404)


api_user_urls = [
    url(r"^api/v1/edit_email$", api_edit_email),
    url(r"^api/v1/edit_password$", api_edit_password),
    url(r"^api/v1/edit_username$", api_edit_username),
    url(r"^api/v1/edit_image$", api_edit_image),
    url(r"^api/v1/edit_name$", api_edit_name),
    url(r"^api/v1/edit_first_name$", api_edit_first_name),
    url(r"^api/v1/edit_last_name$", api_edit_last_name),
    url(r"^api/v1/edit_short_name$", api_edit_short_name),
    url(r"^api/v1/get_user_info$", api_get_user_info),
]