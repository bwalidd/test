from friend.models import FriendRequest, FriendList

def get_friend_requests_or_false(sender,receiver):
    try:
        return FriendRequest.objects.get(sender=sender,receiver=receiver)
    except FriendRequest.DoesNotExist:
        return False