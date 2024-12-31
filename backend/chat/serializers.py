from rest_framework import serializers

class MessageSerializer(serializers.Serializer):
    sender_id = serializers.IntegerField()
    message = serializers.CharField()
