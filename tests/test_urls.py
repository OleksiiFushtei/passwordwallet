from django.test import TestCase
from django.urls import reverse, resolve
from accounts.views import create, account, delete
from users.views import register, login, logout, changepassword, wallet, unlock

import random

class TestUrls(TestCase):

    # Test users.urls
    def test_wallet_url_resolves(self):
        url = reverse('wallet')
        self.assertEquals(resolve(url).func, wallet)

    def test_register_url_resolves(self):
        url = reverse('register')
        self.assertEquals(resolve(url).func, register)

    def test_login_url_resolves(self):
        url = reverse('login')
        self.assertEquals(resolve(url).func, login)

    def test_logout_url_resolves(self):
        url = reverse('logout')
        self.assertEquals(resolve(url).func, logout)

    def test_changepassword_url_resolves(self):
        url = reverse('changepassword')
        self.assertEquals(resolve(url).func, changepassword)

    # TDD
    def test_unlock_url_resolves(self):
        url = reverse('unlock')
        self.assertEquals(resolve(url).func, unlock)

    # Test accounts.urls
    def test_create_url_resolves(self):
        url = reverse('create')
        self.assertEquals(resolve(url).func, create)

    def test_account_url_resolves(self):
        url = reverse('account', args=[random.randint(1,100)])
        self.assertEquals(resolve(url).func, account)

    def test_delete_url_resolves(self):
        url = reverse('delete', args=[random.randint(1,100)])
        self.assertEquals(resolve(url).func, delete)