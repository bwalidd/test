from django.urls import path
from . import consumers

websocket_urlpatterns = [
    path('ws/wsc/<int:user_id>/<int:friend_id>/', consumers.ChatConsumer.as_asgi()),
    path('ws/game-invite/<int:user_id>/<int:friend_id>/', consumers.GameConsumer.as_asgi()),  # Updated path
    path('ws/chat-status/<int:user_id>/<int:friend_id>/', consumers.ChatStatusConsumer.as_asgi()),
]
