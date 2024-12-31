# Send a friend request
from rest_framework import decorators as rest_decorators
from rest_framework import permissions as rest_permissions
from rest_framework import response, status
from django.shortcuts import get_object_or_404
from .models import friendRequest, friendList
from account.models import Account
from django.views.decorators.csrf import csrf_exempt
import logging

# Create a logger instance
logger = logging.getLogger(__name__)


@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def send_friend_request(request, receiver_id):
    # Fetch the receiver (user who will receive the friend request)
    receiver = get_object_or_404(Account, id=receiver_id)
    logger.info(f"Received request: {request.method} to send a friend request to {receiver_id} by {request.user}")
    
    # Check if a friend request already exists
    if friendRequest.objects.filter(sender=request.user, receiver=receiver).exists():
        return response.Response({'detail': 'Friend request already sent.'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Create a new friend request
    friend_request = friendRequest(sender=request.user, receiver=receiver, is_active=True)
    friend_request.save()
    logger.info(f"---(send friend func)----->Friend request created: {friend_request.id}, sender: {friend_request.sender}, receiver: {friend_request.receiver}")

    return response.Response({'detail': 'Friend request sent successfully.'}, status=status.HTTP_201_CREATED)


@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def accept_friend_request(request, sender_id):
    try:
        # Fetch the most recent active friend request from the sender to the logged-in user
        friend_request = friendRequest.objects.filter(
            sender_id=sender_id,
            receiver=request.user,
            is_active=True
        ).latest('timestamp')  # Get the most recent request based on timestamp
    except friendRequest.DoesNotExist:
        logger.error(f"No active friend request found from user {sender_id} to {request.user}")
        return response.Response({'detail': 'No friend request matches the given query.'}, status=status.HTTP_404_NOT_FOUND)
    except friendRequest.MultipleObjectsReturned:
        logger.error(f"Multiple active friend requests found from user {sender_id} to {request.user}")
        return response.Response({'detail': 'Multiple friend requests found. Please handle this manually.'}, status=status.HTTP_409_CONFLICT)

    # Accept the friend request
    friend_request.accept()
    logger.info(f"Friend request accepted between {sender_id} and {request.user}")
    return response.Response({'detail': 'Friend request accepted.'}, status=status.HTTP_200_OK)



@rest_decorators.api_view(["GET"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def check_friend_status(request, user_id):
    """Check the status between the logged-in user and another user."""
    target_user = get_object_or_404(Account, id=user_id)

    if friendList.objects.filter(user=request.user, friends=target_user).exists():
        return response.Response({'status': 'friends'}, status=status.HTTP_200_OK)
    elif friendRequest.objects.filter(sender=request.user, receiver=target_user).exists():
        return response.Response({'status': 'request_sent'}, status=status.HTTP_200_OK)
    elif friendRequest.objects.filter(sender=target_user, receiver=request.user).exists():
        return response.Response({'status': 'request_received'}, status=status.HTTP_200_OK)
    else:
        return response.Response({'status': 'none'}, status=status.HTTP_200_OK)






# Decline or cancel a friend request
@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def decline_friend_request(request, sender_id):
    try:
        # Get the friend request where the authenticated user is the receiver
        friend_request = get_object_or_404(friendRequest, sender_id=sender_id, receiver=request.user)

        # Debugging logs
        print(f"Authenticated user: {request.user}")
        print(f"Friend Request Sender: {friend_request.sender}")
        print(f"Friend Request Receiver: {friend_request.receiver}")
        print(f"Friend Request Data: {friend_request.__dict__}")

        # Decline the friend request
        if friend_request.is_active:
            friend_request.is_active = False
            friend_request.delete()
            return response.Response({'detail': 'Friend request declined.'}, status=status.HTTP_200_OK)
        else:
            return response.Response({'detail': 'This request is no longer active.'}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        print(f"Error: {str(e)}")
        return response.Response({'detail': 'Internal server error.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
