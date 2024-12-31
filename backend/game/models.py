from django.db import models
from django.conf import settings
from django.core.validators import MinValueValidator
import uuid


class GameSession(models.Model):
    session_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    player_one = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="game_sessions_as_player_one",
        on_delete=models.CASCADE,
        null=True,  # Changed to False if player_one is mandatory
        blank=False,  # Changed to False if player_one is mandatory
    )
    player_two = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="game_sessions_as_player_two",
        on_delete=models.CASCADE,
        null=True,  # Changed to False if player_two is mandatory
        blank=False,  # Changed to False if player_two is mandatory
    )
    created_at = models.DateTimeField(auto_now_add=True)
    score_player_1 = models.IntegerField(default=0, validators=[MinValueValidator(0)])
    score_player_2 = models.IntegerField(default=0, validators=[MinValueValidator(0)])
    winner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="game_sessions_won",
        on_delete=models.CASCADE,
        null=True,
        blank=True,  # Winner may be blank if the game is not finished
    )
    loser = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="game_sessions_lost",
        on_delete=models.CASCADE,
        null=True,
        blank=True,  # Loser may be blank if the game is not finished
    )
    paddle_one_y = models.FloatField(default=0)  # Paddle Y-coordinate for player one
    paddle_two_y = models.FloatField(default=0)  # Paddle Y-coordinate for player two
    ball_x = models.FloatField(default=0)  # Ball X-coordinate
    ball_y = models.FloatField(default=0)  # Ball Y-coordinate
    ball_velocity_x = models.FloatField(default=0)
    ball_velocity_y = models.FloatField(default=0)
    is_active = models.BooleanField(default=True)  # Track if the game is ongoing


    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Game Session"
        verbose_name_plural = "Game Sessions"

    def __str__(self):
        return f"Game Session {self.player_two} vs {self.player_one} | {self.session_id}"

