from django.urls import path
from account import views

app_name = "account"

urlpatterns = [
    path('login/', views.loginView),
    path('register/', views.registerView),
    path('refresh-token/', views.CookieTokenRefreshView.as_view()),

    path('login42/', views.login_with_42),
    path('callback/', views.callback),
    path('user42/', views.get_user_data),

    path('logout/', views.logoutView),
    path("user/", views.user),
    path("allusers/",views.allusers),
    path("search/",views.search_users),
    path('userdetails/',views.userDetailView),
    path("user/<int:user_id>/", views.userProfileView),
    path('user/update/', views.update_user),


    # 2fa part

    path('generate-qr/', views.generate_qr_code),
    path("verify-2fa/", views.verify_2fa, name="verify-2fa"),
    path('change-2fa-status/', views.change2fa),
    path('disable-2fa/',views.disable_2fa)

]

