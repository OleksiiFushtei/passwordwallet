from django.db import models
from django.contrib.auth.models import User


class AppUser(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    salt = models.CharField(max_length=20)
    kept_in_hash = models.BooleanField(default=True)

    def __str__(self):
        return self.user.username