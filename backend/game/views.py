from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from .models import GameSession
from django.contrib.auth import get_user_model
from rest_framework.views import APIView
from .models import GameSession
from .serializers import GameSessionSerializer ,GameSessionSerializerDetail
from django.shortcuts import get_object_or_404
from django.db.models import Q


User = get_user_model()

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def start_game(request):
    """
    Start a new game session between two players.
    """
    try:
        player_one_id = request.data.get("player_one")
        player_two_id = request.data.get("player_two")
        session_id = request.data.get("session_id")
        
        # Validate required fields
        if not all([player_one_id, player_two_id, session_id]):
            return Response(
                {"error": "player_one, player_two, and session_id are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Fetch players from the database
        try:
            player_one = User.objects.get(id=player_one_id)
            player_two = User.objects.get(id=player_two_id)
        except User.DoesNotExist:
            return Response(
                {"error": "One or both players do not exist."},
                status=status.HTTP_404_NOT_FOUND
            )

        # Create a new game session
        game_session = GameSession.objects.create(
            session_id=session_id,
            player_one=player_one,
            player_two=player_two,
        )

        return Response(
            {
                "message": "Game session created successfully.",
                "session_id": str(game_session.session_id),
                "player_one": player_one.login,
                "player_two": player_two.login,
            },
            status=status.HTTP_201_CREATED
        )
    except Exception as e:
        return Response(
            {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

 # Ensure you have this serializer defined

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def game_session_detail(request, session_id):
    """
    Retrieve game session details by session ID.
    """
    try:
        # Fetch the game session by session_id
        game_session = GameSession.objects.get(session_id=session_id)
        serializer = GameSessionSerializerDetail(game_session)  # Serialize the game session
        return Response(serializer.data, status=status.HTTP_200_OK)
    except GameSession.DoesNotExist:
        return Response(
            {"error": "Game session not found."},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        return Response(
            {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )



@api_view(['POST'])
@permission_classes([IsAuthenticated])
def postResult(request, session_id):
    """
    Post the result of a game session.
    """
    # Get the game session based on the session_id
    game_session = get_object_or_404(GameSession, session_id=session_id)

    if not game_session.is_active:
        return Response(
            {"error": "Game session is already finalized."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Validate request data
    data = request.data
    winner_login = data.get('winner')
    score_player_1 = data.get('score_player_1')
    score_player_2 = data.get('score_player_2')

    if not winner_login or score_player_1 is None or score_player_2 is None:
        return Response(
            {"error": "Incomplete data provided."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Identify the winner and loser
    try:
        winner = User.objects.get(login=winner_login)
    except User.DoesNotExist:
        return Response(
            {"error": "Winner user does not exist."},
            status=status.HTTP_404_NOT_FOUND,
        )

    loser = game_session.player_one if winner == game_session.player_two else game_session.player_two

    # Update the game session
    game_session.score_player_1 = score_player_1
    game_session.score_player_2 = score_player_2
    game_session.winner = winner
    game_session.loser = loser
    game_session.is_active = False
    game_session.save()

    return Response(
        {
            "message": "Game session result saved successfully.",
            "session_id": game_session.session_id,
            "winner": winner.login,
            "score_player_1": game_session.score_player_1,
            "score_player_2": game_session.score_player_2,
        },
        status=status.HTTP_200_OK,
    )


@api_view(['GET'])
# @permission_classes([IsAuthenticated])
def getAllMatchById(request, user_id):
    """
    Get all game sessions for a user by user ID.
    """
    try:
        user = User.objects.get(id=user_id)
        game_sessions = GameSession.objects.filter(
            Q(player_one=user) | Q(player_two=user),
            is_active=False
        )

        serializer = GameSessionSerializer(game_sessions, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except User.DoesNotExist:
        return Response(
            {"error": "User not found."},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        return Response(
            {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )