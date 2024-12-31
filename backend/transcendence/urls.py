from django.contrib import admin
from django.urls import path,include
from rest_framework_simplejwt.views import TokenObtainPairView
from django.conf import settings
from django.conf.urls.static import static
from chat import routing  # assuming your WebSocket routing is in the chat app



urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('account.urls',namespace='account')),
    path('api/friend/', include('friend.urls',namespace='friend')),
    path('api/chats/', include('chat.urls',namespace='chat')),
    path('api/game/', include('game.urls',namespace='game')),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

websocket_urlpatterns = routing.websocket_urlpatterns


# handler404 = 'profiles.views.error_404'
# handler500 = 'profiles.views.error_500'