import json
from channels.generic.websocket import AsyncWebsocketConsumer
from asgiref.sync import sync_to_async
from .models import GameSession
import random


active_players_for_game_session = {}

class GameConsumer(AsyncWebsocketConsumer):

    async def connect(self):
        # Extract session ID and players from URL
        self.session_id = self.scope['url_route']['kwargs']['session_id']
        self.inviter = self.scope['url_route']['kwargs']['inviter']
        self.invitee = self.scope['url_route']['kwargs']['invitee']

        print(f"-----1----> Inviter: {self.inviter}, Invitee: {self.invitee}")
        self.room_group_name = f'game_{self.session_id}_{self.inviter}_{self.invitee}'

        if self.room_group_name not in active_players_for_game_session:
            active_players_for_game_session[self.room_group_name] = {}

        # Map the channel_name to the player ID
        if self.channel_name not in active_players_for_game_session[self.room_group_name]:
            active_players_for_game_session[self.room_group_name][self.channel_name] = (
                self.inviter if len(active_players_for_game_session[self.room_group_name]) == 0 else self.invitee
            )

        # Add WebSocket connection to the room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.accept()

        # Print active players
        print(f"-----2----> Active players for game session {self.room_group_name}: {active_players_for_game_session[self.room_group_name]}")
        print(f"WebSocket connected for session: {self.session_id}")

    async def disconnect(self, close_code):
        try:
            # Identify the disconnected player
            remaining_players = active_players_for_game_session.get(self.room_group_name, {})
            disconnected_player = remaining_players.pop(self.channel_name, None)

            # Remove WebSocket connection from the room group
            await self.channel_layer.group_discard(
                self.room_group_name,
                self.channel_name
            )

            # Check if only one player remains AND the game is not already over
            if len(remaining_players) == 1:
                # Check if a game over message has not already been sent
                if not hasattr(self, 'game_already_over'):
                    remaining_player_channel = next(iter(remaining_players.keys()))
                    winner = remaining_players[remaining_player_channel]
                    
                    await self.channel_layer.group_send(
                        self.room_group_name,
                        {
                            'type': 'game_over_disconnect',
                            'winner': winner,
                            'score': '5-0',
                            'reason': 'opponent_disconnected',
                            'disconnected_player': disconnected_player
                        }
                    )

                    # Mark the game as over to prevent multiple game over messages
                    self.game_already_over = True

                    # Cleanup the session
                    if self.room_group_name in active_players_for_game_session:
                        del active_players_for_game_session[self.room_group_name]

        except Exception as e:
            print(f"Error in disconnect: {e}")


    async def game_over_disconnect(self, event):
        """
        Handle game over due to player disconnection and notify clients.
        """
        try:
            await self.send(text_data=json.dumps({
                'action': 'game_over_disconnect',
                'winner': event.get('winner'),
                'score': event.get('score'),
                'reason': event.get('reason'),
                'sessionId': event.get('sessionId'),  # Include session ID in the sent message
                'disconnectedPlayer': event.get('disconnectedPlayer')
            }))
        except Exception as e:
            print(f"Error sending game over disconnect message: {e}")



    async def receive(self, text_data):
        """
        Handle incoming WebSocket messages from clients.
        """
        try:
            data = json.loads(text_data)
            action = data.get('action')

            if action == 'paddle_move':
                # Update paddle position for the corresponding player
                player = data.get('player')  # 'player_one' or 'player_two'
                paddle_y = data.get('paddle_y')

                if player == 'player_one':
                    await self.update_paddle_one(paddle_y)
                elif player == 'player_two':
                    await self.update_paddle_two(paddle_y)

            elif action == 'ball_update':
                # Update ball position and velocity
                await self.update_ball(
                    data.get('ball_x'),
                    data.get('ball_y'),
                    data.get('ball_velocity_x'),
                    data.get('ball_velocity_y'),
                )

            elif action == 'score_update':
                # Broadcast score update to all players in the game session
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        'type': 'score_update',
                        'player1_score': data.get('player1_score'),
                        'player2_score': data.get('player2_score')
                    }
                )
            elif action == 'request_ball_reset':
                # Generate a consistent random seed
                reset_seed = random.random()
                
                # Broadcast the reset seed to all players in the game session
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        'type': 'ball_reset',
                        'seed': reset_seed
                    }
                )
            
            elif action == 'game_over':
                # When a game over message is received, broadcast to all players
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        'type': 'game_over',
                        'winner': data.get('winner')
                    }
                )

            # Broadcast the updated data to the group
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'game_update',
                    'data': data
                }
            )
        except Exception as e:
            print(f"Error processing WebSocket message: {e}")

    async def score_update(self, event):
        """
        Send score update event to all clients
        """
        try:
            await self.send(text_data=json.dumps({
                'action': 'score_update',
                'player1_score': event['player1_score'],
                'player2_score': event['player2_score']
            }))
        except Exception as e:
            print(f"Error sending score update: {e}")

    async def game_over(self, event):
        """
        Send game over event to all clients
        """
        try:
            await self.send(text_data=json.dumps({
                'action': 'game_over',
                'winner': event['winner']
            }))
        except Exception as e:
            print(f"Error sending game over message: {e}")


    async def ball_reset(self, event):
        """
        Send ball reset event with a consistent seed to all clients
        """
        try:
            await self.send(text_data=json.dumps({
                'action': 'ball_reset',
                'seed': event['seed']
            }))
        except Exception as e:
            print(f"Error sending ball reset: {e}")

    async def game_update(self, event):
        try:
            # print("Sending game update:", event['data'])
            await self.send(text_data=json.dumps({
                'action': 'update',
                'data': event['data']  # Send the entire game data
            }))
        except Exception as e:
            print(f"Error sending game update: {e}")

    @sync_to_async
    def update_paddle_one(self, paddle_y):
        """
        Update the paddle position for player one in the database.
        """
        try:
            game_session = GameSession.objects.get(session_id=self.session_id)
            game_session.paddle_one_y = paddle_y
            game_session.save()
        except GameSession.DoesNotExist:
            print(f"GameSession not found for session ID: {self.session_id}")

    @sync_to_async
    def update_paddle_two(self, paddle_y):
        """
        Update the paddle position for player two in the database.
        Constrain paddle position between 0 and canvas height - paddle height.
        """
        try:
            game_session = GameSession.objects.get(session_id=self.session_id)
            paddle_y = max(0, min(paddle_y, 400 - 100))  # Assuming canvas height is 400 and paddle height is 100
            game_session.paddle_two_y = paddle_y
            game_session.save()
        except GameSession.DoesNotExist:
            print(f"GameSession not found for session ID: {self.session_id}")


    @sync_to_async
    def update_ball(self, ball_x, ball_y, ball_velocity_x, ball_velocity_y):
        """
        Update the ball's position and velocity in the database.
        """
        try:
            game_session = GameSession.objects.get(session_id=self.session_id)
            game_session.ball_x = ball_x
            game_session.ball_y = ball_y
            game_session.ball_velocity_x = ball_velocity_x
            game_session.ball_velocity_y = ball_velocity_y
            game_session.save()
        except GameSession.DoesNotExist:
            print(f"GameSession not found for session ID: {self.session_id}")

