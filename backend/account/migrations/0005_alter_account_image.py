# Generated by Django 5.1.2 on 2024-12-09 00:29

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0004_alter_account_image'),
    ]

    operations = [
        migrations.AlterField(
            model_name='account',
            name='image',
            field=models.ImageField(blank=True, default='avatars/default_avatar.png', null=True, upload_to='avatars/'),
        ),
    ]
