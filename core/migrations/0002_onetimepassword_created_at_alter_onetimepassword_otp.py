# Generated by Django 4.2.14 on 2024-08-14 14:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='onetimepassword',
            name='created_at',
            field=models.DateTimeField(auto_now_add=True, null=True),
        ),
        migrations.AlterField(
            model_name='onetimepassword',
            name='otp',
            field=models.CharField(blank=True, max_length=6, null=True),
        ),
    ]
