# Generated by Django 3.1.2 on 2021-01-05 14:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0005_auto_20201208_1105'),
    ]

    operations = [
        migrations.AddField(
            model_name='account',
            name='deleted',
            field=models.BooleanField(default=False),
        ),
    ]
