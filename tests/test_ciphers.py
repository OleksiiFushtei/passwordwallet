from django.test import TestCase
from unittest import mock

from users.views import hash_password, hmac_password
from security.aescipher import AESCipher

import hashlib, secrets, hmac

class TestCiphers(TestCase):

    def setUp(self):
        self.password = 'test_password'
        self.salt = 'ceb0605af4ec36e5Fb24e7912e90dc49d'
        self.expected_hash = 'a0d51cb9069ab4abb19da02284dff2d0d2c2c84d2b168b37d7138cb45894458451190fdf9288876143ceb9c399d07ab7f456308b9e02a6bbf924d04c3bafe222'
        self.expected_hmac = 'eacf8eaf8fa08e31021d26e83399be96324ea5206a16b46683bfd702335561f27c433f257955e81691e2f3b8f26c5dc7f908b9ddfc6f56194507a1b489f9f5fe'
        self.hash_function = hash_password
        self.hmac_function = hmac_password

    def testHash_isCorrect(self):
        result = self.hash_function(self, password=self.password, salt=self.salt)
        self.assertEquals(result, self.expected_hash)

    def testHMAC_isCorrect(self):
        result = self.hmac_function(self, password=self.password, salt=self.salt)
        self.assertEquals(result, self.expected_hmac)

class TestAESCipher(TestCase):

    def setUp(self):
        self.salt = 'ec34d3f4d04b2195b596565294bc7b50'
        self.master_password = 'test_password'
        self.mock_cipher = AESCipher(self.master_password)
        self.password = 'test_password'

    def testEnryption_isCorrect(self):
        encrypted_text = self.mock_cipher.encrypt(self.password)
        self.assertEquals(isinstance(encrypted_text, str), True)

    def testDecryption_isCorrect(self):
        decrypted_text = self.mock_cipher.decrypt(self.mock_cipher.encrypt('test_password'))
        self.assertEquals(isinstance(decrypted_text, str), True)
        self.assertEquals(decrypted_text, self.password)
