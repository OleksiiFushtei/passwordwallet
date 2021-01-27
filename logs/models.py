from django.db import models
from django.contrib.auth.models import User


class Log(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    ip_address = models.CharField(max_length=15, blank=False)
    login_time = models.DateTimeField(auto_now=True)
    login_result = models.BooleanField(default=True)
    fail_count = models.IntegerField(default=0)