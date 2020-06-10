from rest_framework import serializers

from StaticAnalyzer import models


class JavaCodeSerializer(serializers.Serializer):
    title = serializers.CharField()
    files = serializers.ListField(
        child=serializers.CharField()
    )
    _hash = serializers.CharField()
    _type = serializers.CharField()
    version = serializers.CharField()


class ReconDataSerializer(serializers.ModelSerializer):
    
    class Meta:
        fields = ("URLS",)
        model = models.StaticAnalyzerAndroid
    