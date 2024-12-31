from rest_framework import serializers
from django.conf import settings
from django.contrib.auth import get_user_model
from friend.models import friendList, friendRequest

class RegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={"input_type": "password"}, write_only=True)
    avatar = serializers.ImageField(required=False)

    class Meta:
        model = get_user_model()
        fields = ("login", "email", "password", "password2", "avatar")
        extra_kwargs = {
            "password": {"write_only": True},
            "password2": {"write_only": True},
        }

    def save(self):
        user = get_user_model()(
            email=self.validated_data["email"],
            login=self.validated_data["login"],
            avatar=self.validated_data.get("avatar"),  # Save avatar if provided
            isIntraUser=False,
        )

        password = self.validated_data["password"]
        password2 = self.validated_data["password2"]

        if password != password2:
            raise serializers.ValidationError({"password": "Passwords do not match!"})

        user.set_password(password)
        user.save()

        return user

# class Registration42Serializer(serializers.ModelSerializer):
#     class Meta:
#         model = get_user_model()
#         fields = ("login", "email", "image")

#     def validate_image(self, value):
#         """
#         Validate and extract the 'medium' image URL from the incoming JSON data.
#         """
#         if isinstance(value, dict):  # Ensure the value is a dictionary
#             # Attempt to extract the 'medium' image URL
#             versions = value.get("versions", {})
#             medium_image = versions.get("medium")
#             if medium_image:
#                 # Optionally validate the URL format
#                 from django.core.validators import URLValidator
#                 from django.core.exceptions import ValidationError

#                 validate = URLValidator()
#                 try:
#                     validate(medium_image)  # Check if it's a valid URL
#                     return medium_image    # Return the valid URL
#                 except ValidationError:
#                     raise serializers.ValidationError("Invalid image URL format.")
        
#         # If the 'medium' image is missing, raise an error
#         raise serializers.ValidationError("Invalid image data. 'medium' URL is required.")

#     def create(self, validated_data):
#         """
#         Create and return a new user instance with the extracted 'medium' image URL.
#         """
#         print(f"2223112={validated_data[image][version][medium]}=22223333")
#         return get_user_model().objects.create(
#             email=validated_data["email"],
#             login=validated_data["login"],
#             image=validated_data.get("image")  # Contains the validated and extracted URL
#         )


class Registration42Serializer(serializers.ModelSerializer):
    # image = serializers.URLField(required=False)  # Use URLField for image URL
    class Meta:
        model = get_user_model()
        fields = ("login", "email", "image")
    
    def save(self):
        user = get_user_model()(
            email=self.validated_data["email"],
            login=self.validated_data["login"],
            image=self.validated_data["image"]["versions"]["medium"]  # Extract the 'medium' image URL  
        )
        user.save()
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(
        style={"input_type": "password"}, write_only=True)


class FriendSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ("id", "login", "image","isIntraUser", "avatar")  # Simplified fields for friends


class AccountSerializer(serializers.ModelSerializer):
    friends = serializers.SerializerMethodField()
    # is_friend = serializers.SerializerMethodField()
    # is_requested = serializers.SerializerMethodField()

    class Meta:
        model = get_user_model()
        fields = ("id", "login", "email", "image","avatar","isIntraUser", "friends","mfa_enabled","mfa_secret","alwaysDisable2fa")

    def get_friends(self, obj):
        try:
            # Retrieve the user's friend list
            friend_list = obj.user_friend_list
            # Serialize the friends using the FriendSerializer (simplified)
            friends = friend_list.friends.all()
            return FriendSerializer(friends, many=True, context=self.context).data
        except friendList.DoesNotExist:
            return []

    def get_is_friend(self, obj):
        request = self.context.get('request', None)
        if request and request.user.is_authenticated:
            return request.user.friends.filter(id=obj.id).exists()
        return False

    def get_is_requested(self, obj):
        request = self.context.get('request', None)
        if request and request.user.is_authenticated:
            return friendRequest.objects.filter(sender=request.user, receiver=obj).exists()
        return False

class AccountDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ("id", "login", "email", "avatar","image","password","isIntraUser","mfa_enabled","mfa_secret","alwaysDisable2fa")


# from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
# from .models import Account

class UserUpdateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = get_user_model()
        fields = ('login', 'email', 'password', 'confirm_password', 'avatar')

    def validate(self, data):
        # Validate that passwords match if provided
        if data.get('password') or data.get('confirm_password'):
            if data.get('password') != data.get('confirm_password'):
                raise serializers.ValidationError({"password": "Passwords do not match."})
        return data

    def update(self, instance, validated_data):
        # Update login and email
        instance.login = validated_data.get('login', instance.login)
        instance.email = validated_data.get('email', instance.email)
        
        # Update avatar if provided
        if 'avatar' in validated_data:
            instance.avatar = validated_data['avatar']
        
        # Update password if both password fields are filled
        password = validated_data.get('password')
        if password:
            instance.set_password(password)
        
        instance.save()
        return instance
