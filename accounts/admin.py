from django.contrib import admin

from .models import Account, Ownership

admin.site.register(Account)
admin.site.register(Ownership)