from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser


class AccountManager(BaseUserManager):
    def create_user(self, email, login, password=None, **kwargs):
        if not email:
            raise ValueError("Email is required")
        if not login:
            raise ValueError("Login is required")

        image = kwargs.get('image', None)

        user = self.model(
            email=self.normalize_email(email),
            login=login,
            image=image,
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, login, password, **kwargs):
        user = self.create_user(
            email=email,
            login=login,
            password=password,
            image=kwargs.get('image', None)
        )
        user.is_admin = True
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user


class Account(AbstractBaseUser):
    email = models.EmailField(unique=True, null=False, blank=False)
    login = models.CharField(max_length=50, unique=True, null=False, blank=False)
    image =models.CharField(max_length=500, blank=True, null=True)
    avatar = models.ImageField(upload_to="avatars/", null=True, blank=True, default="avatars/default_avatar.png")
    is_admin = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    friends = models.ManyToManyField("self", blank=True, symmetrical=True, related_name='account_friends')
    isIntraUser = models.BooleanField(default=True)
    mfa_secret = models.CharField(max_length=32, blank=True, null=True)
    mfa_enabled = models.BooleanField(default=False)
    alwaysDisable2fa = models.BooleanField(default=False)
    
    
    objects = AccountManager()


    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["login"]

    class Meta:
        verbose_name = "Account"
        verbose_name_plural = "Accounts"

    def __str__(self):
        return f"{self.login}"

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True
