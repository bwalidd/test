import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from .models import MychatModel , UserBlocking
from django.contrib.auth import get_user_model
import uuid
from asgiref.sync import sync_to_async
from game.models import GameSession
from django.contrib.auth.models import User

User = get_user_model()

# In-memory dictionary to track online users in room groups
# This is a simplified example; in production, consider using a persistent cache
active_connections = {}

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user_id = int(self.scope['url_route']['kwargs']['user_id'])
        self.friend_id = int(self.scope['url_route']['kwargs']['friend_id'])
        
        # Create a unique room group for the chat
        self.room_group_name = f'chat_{min(self.user_id, self.friend_id)}_{max(self.user_id, self.friend_id)}'
        
        print(f"User {self.user_id} connected to chat with {self.friend_id}")

        # Initialize room group in active connections if not present
        if self.room_group_name not in active_connections:
            active_connections[self.room_group_name] = set()

        # Add current user to the active connections for the room group
        active_connections[self.room_group_name].add(self.user_id)

        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )

        await self.accept()
        print(f"---->user {self.user_id} connected with {self.friend_id} on {self.room_group_name}")

        # Check if both users are online
        await self.notify_online_status()

    async def disconnect(self, close_code):
        # Remove user from active connections for the room group
        if self.room_group_name in active_connections:
            active_connections[self.room_group_name].discard(self.user_id)
            if not active_connections[self.room_group_name]:  # Remove empty room group
                del active_connections[self.room_group_name]

        # Notify the friend that this user is offline
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'user_status',
                'status': 'offline',
                'user_id': self.user_id
            }
        )

        # Leave room group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )
        print(f"---->user {self.user_id} disconnected with {self.friend_id} on {self.room_group_name}")
        
        # Check if both users are still online
        await self.notify_online_status()

    async def receive(self, text_data):
        text_data_json = json.loads(text_data)
        message = text_data_json['msg']

        # Save the message in the database
        await self.save_chat_message(self.user_id, self.friend_id, message)

        # Send message to room group, notifying only the group members
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'chat_message',
                'msg': message,
                'sender': self.user_id  # Include sender info
            }
        )

    async def chat_message(self, event):
        message = event['msg']
        sender = event['sender']

        # Send message to WebSocket only if it's not the sender
        if sender != self.user_id:
            await self.send(text_data=json.dumps({
                'msg': message
            }))

    async def user_status(self, event):
        # Send online/offline status to WebSocket
        status = event['status']
        user_id = event['user_id']
        await self.send(text_data=json.dumps({
            'type': 'status',
            'status': status,
            'user_id': user_id
        }))

    @database_sync_to_async
    def save_chat_message(self, user_id, friend_id, message):
        chat, created = MychatModel.objects.get_or_create(
            me_id=min(user_id, friend_id),
            frnd_id=max(user_id, friend_id),
            defaults={'chats': []}
        )

        # Append the new message to the chat's JSON field
        chat_data = chat.chats or []
        chat_data.append({'sender': user_id, 'message': message})
        chat.chats = chat_data
        chat.save()

    async def notify_online_status(self):
        # Check if both users are online in the room group
        users_in_room = active_connections.get(self.room_group_name, set())
        both_online = {self.user_id, self.friend_id}.issubset(users_in_room)

        # Notify current user about the friend's online status
        await self.send(text_data=json.dumps({
            'type': 'status',
            'status': 'online' if both_online else 'offline',
            'user_id': self.friend_id
        }))

        # Notify friend about the current user's online status if they are also online
        if both_online:
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'user_status',
                    'status': 'online',
                    'user_id': self.user_id
                }
            )



class ChatStatusConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user_id = int(self.scope['url_route']['kwargs']['user_id'])
        self.friend_id = int(self.scope['url_route']['kwargs']['friend_id'])
        
        # Create a unique room group for chat status
        self.room_group_name = f'chat_status_{min(self.user_id, self.friend_id)}_{max(self.user_id, self.friend_id)}'
        
        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )

        await self.accept()
        
        # Check initial chat status
        status = await self.get_chat_status()
        await self.send(text_data=json.dumps({
            'status': status
        }))

    async def disconnect(self, close_code):
        # Leave room group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        # Optional: Handle any incoming messages if needed
        pass

    @database_sync_to_async
    def get_chat_status(self):
        """
        Determine the chat status between two users.
        Possible statuses:
        - 'enabled': Chat is allowed
        - 'blocked': User has blocked the friend
        - 'blocked_by_friend': Friend has blocked the user
        """
        try:
            # Find the user and friend using the custom User model
            user = User.objects.get(id=self.user_id)
            friend = User.objects.get(id=self.friend_id)
            
            # Check if the current user has blocked the friend
            is_user_blocked = UserBlocking.objects.filter(
                blocker=user, 
                blocked=friend
            ).exists()
            
            if is_user_blocked:
                return 'blocked'
            
            # Check if the friend has blocked the current user
            is_friend_blocked = UserBlocking.objects.filter(
                blocker=friend, 
                blocked=user
            ).exists()
            
            if is_friend_blocked:
                return 'blocked_by_friend'
            
            # If no blocking is detected, chat is enabled
            return 'enabled'
        
        except User.DoesNotExist:
            # Handle case where user or friend doesn't exist
            return 'error'

    async def send_status_update(self, event):
        """
        Send status update to the WebSocket
        """
        status = event['status']
        await self.send(text_data=json.dumps({
            'status': status
        }))



class GameConsumer(AsyncWebsocketConsumer):

    async def connect(self):
        self.user_id = self.scope['url_route']['kwargs']['user_id']
        self.friend_id = self.scope['url_route']['kwargs']['friend_id']
        
        self.group_name = f"game_{min(self.user_id, self.friend_id)}_{max(self.user_id, self.friend_id)}"
        
        user_group = f"user_{self.user_id}"
        await self.channel_layer.group_add(
            user_group,
            self.channel_name
        )
        
        await self.accept()

    async def disconnect(self, close_code):
        if hasattr(self, 'group_name'):
            await self.channel_layer.group_discard(
                self.group_name,
                self.channel_name
            )
        
    async def receive(self, text_data):
        try:
            data = json.loads(text_data)

            if data['type'] == 'game_invitation':
                recipient_id = data.get('to')
                message = data.get('message')

                if not recipient_id or not message:
                    return

                to_user_group = f"user_{recipient_id}"
                await self.channel_layer.group_send(
                    to_user_group,
                    {
                        "type": "game_invitation_message",
                        "from": self.user_id,
                        "message": message
                    }
                )

            elif data['type'] == 'game_response':
                recipient_id = data.get('to')
                response = data.get('response')

                if not recipient_id or not response:
                    return

                to_user_group = f"user_{recipient_id}"

                if response == "accepted":
                    # Generate a unique session ID
                    session_id = str(uuid.uuid4())

                    # Create a GameSession object
                    await self.create_game_session(self.user_id, recipient_id, session_id)

                    # Notify both players to navigate to /play
                    for user_id in [self.user_id, recipient_id]:
                        await self.channel_layer.group_send(
                            f"user_{user_id}",
                            {
                                "type": "navigate_to_play",
                                "from": self.user_id,
                                "to": recipient_id,
                                "session_id": session_id
                            }
                        )
                else:
                    await self.channel_layer.group_send(
                        to_user_group,
                        {
                            "type": "game_response_message",
                            "from": self.user_id,
                            "response": response
                        }
                    )

        except Exception as e:
            print(f"Error: {e}")

    async def game_invitation_message(self, event):
        await self.send(text_data=json.dumps({
            "type": "game_invitation",
            "from": event["from"],
            "message": event["message"]
        }))
    
    async def game_response_message(self, event):
        await self.send(text_data=json.dumps({
            "type": "game_response",
            "from": event["from"],
            "response": event["response"]
        }))

    async def navigate_to_play(self, event):
        await self.send(text_data=json.dumps({
            "type": "navigate_to_play",
            "from": event["from"],
            "to": event["to"],
            "session_id": event["session_id"]
        }))

    async def create_game_session(self, player_one_id, player_two_id, session_id):
        """
        Create a GameSession object in the database.
        """
        try:
            player_one = await sync_to_async(User.objects.get)(id=player_one_id)
            player_two = await sync_to_async(User.objects.get)(id=player_two_id)

            await sync_to_async(GameSession.objects.create)(
                session_id=session_id,
                player_one=player_one,
                player_two=player_two
            )

            print(f"Game session created: {session_id}")
        except Exception as e:
            print(f"Error creating game session: {e}")
