from django.db import models
from django.conf import settings
import json

class MychatModel(models.Model):
    me = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='it_me')
    frnd = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='my_frnd')
    chats = models.JSONField(default=list)

    class Meta:
        unique_together = ('me', 'frnd')

class UserBlocking(models.Model):
    blocker = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='blocked_users_set'
    )
    blocked = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='blocked_by_users_set'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('blocker', 'blocked')
        verbose_name_plural = 'User Blockings'

    def __str__(self):
        return f"{self.blocker.login} blocked {self.blocked.login}"