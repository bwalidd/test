# Generated by Django 5.1.2 on 2024-12-11 15:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0010_account_mfa_enabled_account_mfa_secret'),
    ]

    operations = [
        migrations.AlterField(
            model_name='account',
            name='mfa_secret',
            field=models.CharField(blank=True, max_length=32, null=True),
        ),
    ]
