from django.urls import path

from . import views

urlpatterns = [
    path('login', views.login, name='login'),
    path('register', views.register, name='register'),
    path('logout', views.logout, name='logout'),
    path('wallet/read', views.wallet_read, name='wallet_read'),
    path('wallet/edit', views.wallet_edit, name='wallet_edit'),
    path('changepassword', views.changepassword, name='changepassword'),
    path('unlock', views.unlock, name='unlock'),
]