# Generated by Django 3.1.2 on 2020-12-08 09:38

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0001_initial'),
        ('accounts', '0003_auto_20201206_1540'),
    ]

    operations = [
        migrations.CreateModel(
            name='AppUserHasAccounts',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('is_owner', models.BooleanField(default=True)),
                ('account', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='accounts.account')),
                ('appuser', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='users.appuser')),
            ],
        ),
        migrations.AddField(
            model_name='account',
            name='appusers',
            field=models.ManyToManyField(through='accounts.AppUserHasAccounts', to='users.AppUser'),
        ),
    ]