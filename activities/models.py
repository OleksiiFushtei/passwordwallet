from django.db import models
from django.contrib.auth.models import User

from users.models import AppUser
from accounts.models import Account

# Create your models here.
class Activity(models.Model):
    appuser = models.ForeignKey(AppUser, on_delete=models.CASCADE)
    account = models.ForeignKey(Account, on_delete=models.CASCADE)
    previous_value = models.CharField(max_length=256)
    current_value = models.CharField(max_length=256, blank=True)
    time = models.DateTimeField(auto_now_add=True)
    action = models.CharField(max_length=10, blank=True)

    def __str__(self):
        return self.appuser.user.username + ' ' + self.account.web_address + ' ' + self.action