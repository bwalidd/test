from rest_framework import permissions as rest_permissions
from rest_framework import decorators as rest_decorators
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from .models import MychatModel , UserBlocking
from django.db.models import Q
from django.contrib.auth import get_user_model
from rest_framework import status

User = get_user_model()

@rest_decorators.api_view(["GET"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def get_chat_messages(request, user_id, friend_id):
    # Ensure the logged-in user is either `user_id` or `friend_id`
    if request.user.id not in [user_id, friend_id]:
        return Response({'error': 'Unauthorized access'}, status=403)

    # Query for a chat record between `user_id` and `friend_id`
    chat_record = MychatModel.objects.filter(
        (Q(me_id=user_id) & Q(frnd_id=friend_id)) |
        (Q(me_id=friend_id) & Q(frnd_id=user_id))
    ).first()

    if chat_record:
        messages = chat_record.chats  # Retrieve the messages from the `chats` JSON field
    else:
        messages = []

    # Return the chat messages as JSON response
    return Response({'messages': messages})


@rest_decorators.api_view(['POST'])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def block_friend(request, blocker_id, blocked_id):
    """
    API endpoint to block a friend using both blocker_id and blocked_id from the URL.
    """
    # Ensure the logged-in user is the blocker
    if request.user.id != blocker_id:
        return Response({'error': 'You are not authorized to block on behalf of this user'}, status=status.HTTP_403_FORBIDDEN)

    try:
        blocked_user = User.objects.get(id=blocked_id)

        # Check if the blocking relationship already exists
        if UserBlocking.objects.filter(blocker_id=blocker_id, blocked_id=blocked_id).exists():
            return Response({'message': 'User is already blocked'}, status=status.HTTP_200_OK)

        # Create the blocking relationship
        UserBlocking.objects.create(blocker_id=blocker_id, blocked_id=blocked_id)
        return Response({'message': f'You have blocked {blocked_user.login}'}, status=status.HTTP_201_CREATED)

    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@rest_decorators.api_view(['POST'])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def unblock_friend(request, blocker_id, blocked_id):
    """
    API endpoint to unblock a friend using both blocker_id and blocked_id from the URL.
    """
    # Ensure the logged-in user is the blocker
    if request.user.id != blocker_id:
        return Response({'error': 'You are not authorized to unblock on behalf of this user'}, status=status.HTTP_403_FORBIDDEN)

    try:
        blocked_user = User.objects.get(id=blocked_id)

        # Check if the blocking relationship exists
        blocking_relationship = UserBlocking.objects.filter(blocker_id=blocker_id, blocked_id=blocked_id).first()
        if blocking_relationship:
            blocking_relationship.delete()
            return Response({'message': f'You have unblocked {blocked_user.login}'}, status=status.HTTP_200_OK)

        return Response({'message': 'User is not blocked'}, status=status.HTTP_200_OK)

    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)