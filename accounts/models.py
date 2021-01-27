from django.db import models

from users.models import AppUser

class Account(models.Model):
    password = models.CharField(max_length=256)
    web_address = models.CharField(max_length=256)
    description = models.CharField(max_length=256)
    login = models.CharField(max_length=30)
    deleted = models.BooleanField(default=False)
    appusers = models.ManyToManyField(AppUser, through='Ownership')

    def __str__(self):
        return self.login

class Ownership(models.Model):
    appuser = models.ForeignKey(AppUser, on_delete=models.CASCADE)
    account = models.ForeignKey(Account, on_delete=models.CASCADE)
    is_owner = models.BooleanField(default=True)

    def __str__(self):
        return self.appuser.user.username + ' ' + self.account.login + ' ' + str(self.is_owner)