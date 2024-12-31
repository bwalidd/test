from django.urls import re_path, path
from .consumers import GameConsumer

websocket_urlpatterns = [
    path('ws/game/<str:session_id>/<int:inviter>/<int:invitee>/', GameConsumer.as_asgi()),
    # re_path(r'ws/game/(?P<session_id>[^/]+)/$', GameConsumer.as_asgi()),
]

