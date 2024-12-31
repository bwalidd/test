# friend/serializers.py
from rest_framework import serializers
from django.contrib.auth import get_user_model

class FriendSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ("id", "login", "image","isIntraUser","avatar")  # Include the necessary fields
