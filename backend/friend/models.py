from django.db import models
from django.conf import settings
from django.utils import timezone

# Create your models here.

class friendList(models.Model):
    
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='user_friend_list')
    friends = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='friend_list_friends')

    def __str__(self):
        return self.user.login

    def add_friend(self, account):
        """
        Add a new friend and ensure reciprocity
        """
        if account not in self.friends.all():
            self.friends.add(account)  # Add to current user's list
            friend_list = friendList.objects.get(user=account)
            friend_list.friends.add(self.user)

    def remove_friend(self, account):  # Indentation fixed here
        """
        Remove a friend and ensure reciprocity
        """
        if account in self.friends.all():
            self.friends.remove(account)  # Remove from current user's list
            friend_list = friendList.objects.get(user=account)
            friend_list.friends.remove(self.user)
        
    def unfriend(self, removee):
        """
        remove a friend
        """
        remover_friends_list = self  # person who is removing the friend

        # remove friend from remover friend list
        remover_friends_list.remove_friend(removee)

        friends_list = friendList.objects.get(user=removee)  # person who is being removed
        friends_list.remove_friend(self.user)

    def is_mutual_friend(self, friend):
        """
        Check if a user is a mutual friend
        """
        return friend in self.friends.all()

class friendRequest(models.Model):

    # request_id = models.AutoField(primary_key=True) 
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='sender')
    receiver = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='receiver')
    is_active = models.BooleanField(blank=True, null=False, default=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.sender.login

    def accept(self):
        """
        Accept a friend request and update both sender and receiver friend lists
        """
        # Ensure the receiver has a friend list, or create one
        receiver_friend_list, created = friendList.objects.get_or_create(user=self.receiver)
        
        # Ensure the sender has a friend list, or create one
        sender_friend_list, created = friendList.objects.get_or_create(user=self.sender)

        # Add the sender to the receiver's friend list and vice versa (for friendList model)
        receiver_friend_list.add_friend(self.sender)
        sender_friend_list.add_friend(self.receiver)
        
        # Also add each other to the friends field in the Account model (for UI-related updates)
        self.receiver.friends.add(self.sender)
        self.sender.friends.add(self.receiver)

        # Mark the request as inactive (accepted)
        self.is_active = False
        self.save()



    def decline(self):
        """
        decline a friend request
        """
        self.is_active = False
        self.save()
        
    def cancel(self):
        """
        cancel a friend request
        """
        self.is_active = False
        self.save()