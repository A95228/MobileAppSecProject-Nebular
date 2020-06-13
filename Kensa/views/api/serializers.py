from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from StaticAnalyzer import models


class ReconDataSerializer(serializers.ModelSerializer):
    class Meta:
        fields = ("URLS",)
        model = models.StaticAnalyzerAndroid


class ScanAppSerializer(serializers.Serializer):
    scan_type = serializers.CharField()
    md5 = serializers.CharField()
    organization_id = serializers.IntegerField()
    file_name = serializers.CharField()


class KensaTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        return token
