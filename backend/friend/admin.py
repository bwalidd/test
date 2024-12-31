from django.contrib import admin
from .models import friendList, friendRequest


# Register your models here.
class FriendListAdmin(admin.ModelAdmin):
    list_filter = ['user']
    list_display = ['user']
    search_field = ['user']
    readonly_fields = ['user']

    class Meta:
        model = friendList

admin.site.register(friendList, FriendListAdmin)

class FriendRequestAdmin(admin.ModelAdmin):
    list_filter = ['sender', 'receiver']
    list_display = ['sender', 'receiver']
    search_field = ['sender__login','sender__email','receiver__email', 'receiver__login']
    

    class Meta:
        model = friendRequest

admin.site.register(friendRequest, FriendRequestAdmin)