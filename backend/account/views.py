from django.contrib.auth import authenticate
from django.conf import settings
from django.middleware import csrf
from rest_framework import exceptions as rest_exceptions, response, decorators as rest_decorators, permissions as rest_permissions
from rest_framework_simplejwt import tokens, views as jwt_views, serializers as jwt_serializers, exceptions as jwt_exceptions
from account import serializers, models
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from .serializers import UserUpdateSerializer, Registration42Serializer
import logging
from django.http import JsonResponse
from django.shortcuts import redirect
import requests
from rest_framework.response import Response 
from .models import Account  
import pyotp
import qrcode
import io
import base64


def get_user_tokens(user):
    refresh = tokens.RefreshToken.for_user(user)
    return {
        "refresh_token": str(refresh),
        "access_token": str(refresh.access_token)
    }

def set_csrf_token(response, request):
    response["X-CSRFToken"] = csrf.get_token(request)


def get_user_tokens(user):
    refresh = tokens.RefreshToken.for_user(user)
    return {
        "refresh_token": str(refresh),
        "access_token": str(refresh.access_token)
    }


@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([])
def loginView(request):
    serializer = serializers.LoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    email = serializer.validated_data["email"]
    password = serializer.validated_data["password"]

    user = authenticate(email=email, password=password)

    if user is not None:
        tokens = get_user_tokens(user)
        res = response.Response()
        res.set_cookie(
            key=settings.SIMPLE_JWT['AUTH_COOKIE'],
            value=tokens["access_token"],
            expires=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
            secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
            httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
            samesite='None'
        )

        res.set_cookie(
            key=settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],
            value=tokens["refresh_token"],
            expires=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
            secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
            httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
            samesite='None'
        )

        # Add user data to the response, including avatar
        user_image_url = (
            request.build_absolute_uri(user.image)
            if user.image
            else None
        )

        user_data = {
            "login": user.login,
            "email": user.email,
            "image": user_image_url,
            "csrf_token": csrf.get_token(request),  # Include CSRF token here
            "mfa_enabled": user.mfa_enabled,
            "isIntraUser": user.isIntraUser,
            "mfa_secret": user.mfa_secret,
            "alwaysDisable2fa": user.alwaysDisable2fa
        }
        res.data = {**tokens, **user_data}

        print("------->" + res.data["csrf_token"] + "------->")  # Log the CSRF token for debugging
        return res
    raise rest_exceptions.AuthenticationFailed(
        "Email or Password is incorrect!"
    )




logger = logging.getLogger(__name__)

@rest_decorators.api_view(['POST'])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def logoutView(request):
    """
    Handles user logout by clearing cookies. Blacklisting is optional.
    """
    try:
        refresh_token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
        if not refresh_token:
            logger.warning("Logout attempted without a refresh token.")
            res = response.Response(
                {"detail": "No refresh token found."}, 
                status=status.HTTP_400_BAD_REQUEST
            )
            clear_auth_cookies(res)
            return res

        # Remove token.blacklist() if blacklisting is not needed
        try:
            token = tokens.RefreshToken(refresh_token)
            # Uncomment if blacklist functionality is enabled
            # token.blacklist()  
            logger.info("Refresh token processed.")
        except tokens.TokenError as e:
            logger.error(f"Token processing error: {str(e)}")

        res = response.Response({"detail": "Successfully logged out."}, status=status.HTTP_200_OK)
        clear_auth_cookies(res)
        return res

    except Exception as e:
        logger.exception("Unexpected error during logout.")
        raise rest_exceptions.ParseError("An unexpected error occurred during logout.")


def clear_auth_cookies(response):
    """
    Utility function to clear authentication-related cookies.
    """
    cookies_to_clear = [
        settings.SIMPLE_JWT['AUTH_COOKIE'], 
        settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH']
    ]
    for cookie in cookies_to_clear:
        response.delete_cookie(cookie, samesite='None')
    response.delete_cookie("X-CSRFToken", samesite='None')
    response.delete_cookie("csrftoken", samesite='None')



@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([])
def registerView(request):
    serializer = serializers.RegistrationSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    user = serializer.save()

    if user is not None:
        return response.Response("Registered!")
    return rest_exceptions.AuthenticationFailed("Invalid credentials!")


class CookieTokenRefreshSerializer(jwt_serializers.TokenRefreshSerializer):
    refresh = None

    def validate(self, attrs):
        attrs['refresh'] = self.context['request'].COOKIES.get('refresh')
        if attrs['refresh']:
            return super().validate(attrs)
        else:
            raise jwt_exceptions.InvalidToken(
                'No valid token found in cookie \'refresh\'')


class CookieTokenRefreshView(jwt_views.TokenRefreshView):
    serializer_class = CookieTokenRefreshSerializer

    def finalize_response(self, request, response, *args, **kwargs):
        if response.data.get("refresh"):
            response.set_cookie(
                key=settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],
                value=response.data['refresh'],
                expires=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
                secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
            )

            del response.data["refresh"]
        response["X-CSRFToken"] = request.COOKIES.get("csrftoken")
        return super().finalize_response(request, response, *args, **kwargs)


@rest_decorators.api_view(["GET"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def user(request):
    try:
        user = models.Account.objects.get(id=request.user.id)
    except models.Account.DoesNotExist:
        return response.Response(status=404)

    serializer = serializers.AccountSerializer(user)
    res = response.Response(serializer.data)

    # Set CSRF token in the response
    set_csrf_token(res, request)

    return res

@api_view(["GET"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def generate_qr_code(request):
    user = request.user


    if not user.mfa_secret:
        user.mfa_secret = pyotp.random_base32()
        user.save()

    otp_uri = pyotp.totp.TOTP(user.mfa_secret).provisioning_uri(
        name=user.email,
        issuer_name=user.login
    )

    # Generate the QR Code
    qr = qrcode.make(otp_uri)
    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")
    buffer.seek(0)
    qr_code = base64.b64encode(buffer.getvalue()).decode("utf-8")

    return Response({"qr_code": f"data:image/png;base64,{qr_code}"})


@rest_decorators.api_view(["GET"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def userDetailView(request):
    try:
        user = models.Account.objects.get(id=request.user.id)
    except models.Account.DoesNotExist:
        return response.Response(status=404)

    serializer = serializers.AccountDetailSerializer(user)
    return response.Response(serializer.data)



@rest_decorators.api_view(["GET"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def allusers(request):
    users = models.Account.objects.all()  # Fetch all users
    serializer = serializers.AccountSerializer(users, many=True)  # Serialize multiple users
    return response.Response(serializer.data)  # Return serialized data



@rest_decorators.api_view(["GET"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def disable_2fa(request):
    user = request.user
    user.mfa_enabled = False
    user.mfa_secret = None
    user.alwaysDisable2fa = True
    user.save()
    return Response({"mfa_enabled": user.mfa_enabled, "mfa_secret": user.mfa_secret, "alwaysDisable2fa": user.alwaysDisable2fa})


@api_view(["POST"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def verify_2fa(request):
    user = request.user
    code = request.data.get("code", "")

    if not user.mfa_secret:
        return Response({"error": "2FA not enabled for this user."}, status=400)

    totp = pyotp.TOTP(user.mfa_secret)
    if totp.verify(code):
        return Response({"message": "2FA verified successfully!"})
    else:
        return Response({"error": "Invalid 2FA code."}, status=400)




@rest_decorators.api_view(["GET"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def search_users(request):
    search_string = request.GET.get("search", "").strip()

    if not search_string:
        return response.Response({"error": "Search string is required"}, status=400)

    users = models.Account.objects.filter(login__icontains=search_string)
    serializer = serializers.AccountSerializer(users, many=True)
    return response.Response(serializer.data)



@api_view(["GET"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def change2fa(request):
    user = request.user
    print('-------------------------------------')
    print('change',user.login ,'2fa status' , user.mfa_enabled)
    print('-------------------------------------')
    user.mfa_enabled = True
    print('change',user.login ,'2fa status' , user.mfa_enabled)
    print('-------------------------------------')
    user.save()
    return Response({"mfa_enabled": user.mfa_enabled})


@rest_decorators.api_view(["GET"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def userProfileView(request, user_id):
    # Fetch the user by ID
    user = get_object_or_404(models.Account, id=user_id)
    
    # Serialize the user data
    serializer = serializers.AccountSerializer(user)
    
    # # Check if the user is a friend of the requesting user
    # is_friend = request.user.friends.filter(id=user_id).exists()

    # # Check if a friend request has been sent
    # is_requested = models.friendRequest.objects.filter(sender=request.user, receiver=user).exists()
    # Add the is_friend and is_requested status to the serialized data
    response_data = serializer.data
    # response_data['is_friend'] = is_friend
    # response_data['is_requested'] = is_requested

    return response.Response(response_data)


@rest_decorators.api_view(["PUT"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def update_user(request):
    user = request.user  # Current authenticated user
    serializer = UserUpdateSerializer(user, data=request.data, partial=True)
    
    if serializer.is_valid():
        serializer.save()
        return response.Response(serializer.data, status=status.HTTP_200_OK)

    print("-------->",serializer.data)
    return response.Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



# Replace these with your 42 API credentials
# CLIENT_ID = 'u-s4t2ud-1f0cfd27126006ab0264efcc3e6e81e4d4e26e212130321a3848cd0d580e2b74'
# CLIENT_SECRET = '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'
# REDIRECT_URI = 'http://localhost:8001/api/auth/callback/'

# 42 Intra API endpoints

AUTHH_URL = 'https://api.intra.42.fr/oauth/authorize'
TOKENN_URL = 'https://api.intra.42.fr/oauth/token'

def login_with_42(request):
    """
    Redirect user to the 42 OAuth authorization page.
    """
    params = {
        'client_id': settings.CLIENT_ID,
        'redirect_uri': settings.REDIRECT_URI,
        'response_type': 'code',
    }
    
    auth_url = f"{AUTHH_URL}?client_id={settings.CLIENT_ID}&redirect_uri={settings.REDIRECT_URI}&response_type=code"
    return redirect(auth_url)
    
    return redirect(auth_url)

def callback(request):
    """
    Handle the callback from 42 and exchange code for a token.
    """
    code = request.GET.get('code')

    if not code:
        return JsonResponse({'error': 'Authorization code not provided'}, status=400)

    # Exchange authorization code for access token
    data = {
        'grant_type': 'authorization_code',
        'client_id': settings.CLIENT_ID,
        'client_secret': settings.CLIENT_SECRET,
        'code': code,
        'redirect_uri': settings.REDIRECT_URI,
    }
    response = requests.post(TOKENN_URL, data=data)
    if response.status_code != 200:
        return JsonResponse({'error': 'Failed to retrieve access token'}, status=response.status_code)

    token_data = response.json()
    access_token = token_data.get('access_token')
    refresh_token = token_data.get('refresh_token')

    # Store tokens in the session
    request.session['access_token_0auth'] = access_token
    request.session['refresh_token_0auth'] = refresh_token

    # Redirect to fetch user data
    return redirect("http://localhost:8001/api/auth/user42/")

def get_user_data(request):
    """
    Fetch user data from 42 API using the access token.
    """
    access_token = request.session.get('access_token_0auth')
    if not access_token:
        return JsonResponse({'error': 'Access token required'}, status=401)

    headers = {'Authorization': f'Bearer {access_token}'}
    user_info_url = 'https://api.intra.42.fr/v2/me'
    response = requests.get(user_info_url, headers=headers)

    if response.status_code != 200:
        return JsonResponse({'error': 'Failed to fetch user data'}, status=response.status_code)

    data = response.json()
    image_url = data.get("image", {}).get("versions", {}).get("medium")
    email = data.get("email")
    login = data.get("login")

    user_data = {
        "login": login,
        "email": email,
        "image": image_url
    }

    user, created = Account.objects.get_or_create(
        login=user_data["login"],
        defaults=user_data
    )

    tokens = get_user_tokens(user)
    response = redirect('http://localhost:8004/')
    response.set_cookie(
        key=settings.SIMPLE_JWT['AUTH_COOKIE'],
        value=tokens["access_token"],
        httponly=True,
        secure=False,
        samesite='Strict',
    )
    response.set_cookie(
        key=settings.SIMPLE_JWT["AUTH_COOKIE_REFRESH"],
        value=tokens["refresh_token"],
        httponly=True,
        secure=True,
        samesite='Strict',
    )
    response['Access-Control-Allow-Origin'] = 'http://localhost:8004'
    response['Access-Control-Allow-Credentials'] = 'true'

    return response