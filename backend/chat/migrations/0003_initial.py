# Generated by Django 5.1.2 on 2024-10-20 16:39

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('chat', '0002_delete_chatmodel'),
    ]

    operations = [
        migrations.CreateModel(
            name='chatModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('sender', models.CharField(default=None, max_length=100)),
                ('message', models.CharField(blank=True, null=True)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('thread_name', models.CharField(blank=True, max_length=100, null=True)),
            ],
        ),
    ]
