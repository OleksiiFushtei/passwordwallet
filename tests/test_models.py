from django.test import TestCase
from django.contrib.auth.models import User
from users.models import AppUser
from accounts.models import Account
from logs.models import Log

import secrets
from unittest import mock
import datetime
import re

class TestAppUserModel(TestCase):

    def setUp(self):
        # Mock user
        self.mock_user = mock.Mock(User)
        self.mock_user.username = 'test_username'
        self.mock_user.password = 'test_password'
        # Mock appuser 1
        self.kept_in_hash = True
        self.mock_appuser1 = mock.Mock(AppUser)
        self.mock_appuser1.user = self.mock_user
        self.mock_appuser1.salt = secrets.token_hex(8)
        self.mock_appuser1.kept_in_hash = self.kept_in_hash
        # Mock appuser 2
        self.kept_in_hash = False
        self.mock_appuser2 = mock.Mock(AppUser)
        self.mock_appuser2.user = self.mock_user
        self.mock_appuser2.salt = secrets.token_hex(8)
        self.mock_appuser2.kept_in_hash = self.kept_in_hash

    def testAppUserUsername_isCorrect(self):
        self.assertEquals(self.mock_appuser1.user.username, 'test_username')

    def testAppUserEncyptMethod_IsCorrect_WhenHashIsChosen(self):
        self.kept_in_hash = True
        self.assertEquals(self.mock_appuser1.kept_in_hash, True)

    def testAppUserEncyptMethod_IsCorrect_WhenHMACIsChosen(self):   
        self.kept_in_hash = False
        self.assertEquals(self.mock_appuser2.kept_in_hash, False)


class TestAccountModel(TestCase):

    def setUp(self):
        # Mock user
        self.mock_user = mock.Mock(User)
        self.mock_user.username = 'test_username'
        self.mock_user.password = 'test_password'
        self.kept_in_hash = True
        # Mock appuser
        self.mock_appuser = mock.Mock(AppUser)
        self.mock_appuser.user = self.mock_user
        self.mock_appuser.salt = secrets.token_hex(8)
        self.mock_appuser.kept_in_hash = self.kept_in_hash
        # Mock account
        self.mock_account = mock.Mock(Account)
        self.mock_account.password = 'test_password'
        self.mock_account.appuser = self.mock_appuser
        self.mock_account.web_address = 'test_web_address'
        self.mock_account.description = 'test_description'
        self.mock_account.login = 'test_login'

    def testAccountAppuser_isCorrect(self):
        self.assertEquals(self.mock_account.appuser, self.mock_appuser)


# TDD part
class TestLogModel(TestCase):

    def setUp(self):
        # Mock user
        self.mock_user = mock.Mock(User)
        self.mock_user.username = 'test_username'
        self.mock_user.password = 'test_password'
        # Mock log
        self.login_time = datetime.datetime.now()
        self.mock_log = mock.Mock(Log)
        self.mock_log.user = self.mock_user
        self.mock_log.ip_address = '192.168.10.10'
        self.mock_log.login_time = self.login_time
        self.mock_log.login_result = True
        self.mock_log.fail_count = 0

    def testLogUser_isCorrect(self):
        self.assertEquals(self.mock_log.user, self.mock_user)

    def testLogDateTime_isCorrect(self):
        self.assertEquals(self.mock_log.login_time, self.login_time)