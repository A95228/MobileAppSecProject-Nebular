from django.shortcuts import render
from django.views.generic import UpdateView
# Create your views here.
from rest_framework import serializers, status
from rest_framework.response import Response
from django.db import IntegrityError
from users.models import User


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