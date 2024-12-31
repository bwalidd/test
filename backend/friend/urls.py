from django.urls import path
from . import views

app_name = 'friend' 

urlpatterns = [
    path('send-request/<int:receiver_id>/', views.send_friend_request, name='send_friend_request'),
    path('accept-request/<int:sender_id>/', views.accept_friend_request, name='accept_friend_request'),
    path('check-status/<int:user_id>/', views.check_friend_status, name='check_friend_status'),
    path('decline-request/<int:sender_id>/', views.decline_friend_request, name='decline_friend_request'),
]
