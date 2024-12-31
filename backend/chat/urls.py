from django.urls import path
from . import views

app_name = 'chat'


urlpatterns = [
    # Other endpoints...
    path('messages/<int:user_id>/<int:friend_id>/', views.get_chat_messages, name='get_chat_messages'),
    path('block/<int:blocker_id>/<int:blocked_id>/', views.block_friend, name='block_friend'),
    path('unblock/<int:blocker_id>/<int:blocked_id>/', views.unblock_friend, name='unblock_friend'),
]
