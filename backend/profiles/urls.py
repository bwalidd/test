from django.contrib import admin
from django.urls import path,include
from . import views

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('profile/', views.myprofile, name='profile'),
    # path('get_current_user/', views.current_user, name='current_user'),
]
