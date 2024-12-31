from django.urls import path
from . import views

app_name = 'game'

urlpatterns = [
    path('start/', views.start_game, name='start_game'),  # Create game session
    path('details/<str:session_id>/', views.game_session_detail, name='game_session_detail'),  # Get game session details
    path('result/<str:session_id>/', views.postResult, name='postResult'),  # Post game result
    path('allmygames/<int:user_id>/', views.getAllMatchById, name='allMyGames'),  # Get all games for the authenticated user
]
