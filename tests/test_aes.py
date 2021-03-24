#!/usr/bin/python3

# Copyright 2021 Djones A. Boni
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from unit_test_c_with_python.load_c import load

import unittest
import os
import random

AES_BLOCK_LEN = 16

# Dicrionaries to hold modules and ffis
module, ffi = {}, {}

# Compile several modules with different key length
for AES_KEY_LEN in (16, 24, 32):

  # Every module have its own name
  module_name = 'aes_%d_' % AES_KEY_LEN

  source_files = [
    '../source/aes.c',
  ]

  include_paths = [
    '../include',
  ]

  # Each module has one key length
  compiler_options = [
    '-std=c90',
    '-pedantic',
    '-DAES_KEY_LEN=%d' % AES_KEY_LEN
  ]

  module[AES_KEY_LEN], ffi[AES_KEY_LEN] = load(
      source_files, include_paths, compiler_options,
      module_name=module_name)

from Crypto.Cipher import AES

class TestECBEncrypt(unittest.TestCase):

  def testECBEncryptZeros(self):
    # Test all the modules
    # AES-128, AES-192, AES-256
    for AES_KEY_LEN in (16, 24, 32):
      key = b'\x00' * AES_KEY_LEN
      plain = b'\x00' * AES_BLOCK_LEN

      cipher_module = b'\x00' * AES_BLOCK_LEN
      module[AES_KEY_LEN].AES_ECBEncrypt(key, plain, cipher_module)

      # The correct implementation is automatically selected with by the
      # key length
      cipher_reference = AES.new(key, AES.MODE_ECB).encrypt(plain)

      self.assertEqual(cipher_module, cipher_reference)

  def testECBEncryptRandom(self):
    for AES_KEY_LEN in (16, 24, 32):
      for count in range(1024):
        key = os.urandom(AES_KEY_LEN)
        plain = os.urandom(AES_BLOCK_LEN)

        cipher_module = b'\x00' * AES_BLOCK_LEN
        module[AES_KEY_LEN].AES_ECBEncrypt(key, plain, cipher_module)

        cipher_reference = AES.new(key, AES.MODE_ECB).encrypt(plain)

        self.assertEqual(cipher_module, cipher_reference)

class TestECBDecrypt(unittest.TestCase):

  def testECBDecryptZeros(self):
    for AES_KEY_LEN in (16, 24, 32):
      key = b'\x00' * AES_KEY_LEN
      cipher = b'\x00' * AES_BLOCK_LEN

      plain_module = b'\x00' * AES_BLOCK_LEN
      module[AES_KEY_LEN].AES_ECBDecrypt(key, cipher, plain_module)

      plain_reference = AES.new(key, AES.MODE_ECB).decrypt(cipher)

      self.assertEqual(plain_module, plain_reference)

  def testECBDecryptRandom(self):
    for AES_KEY_LEN in (16, 24, 32):
      for count in range(1024):
        key = os.urandom(AES_KEY_LEN)
        cipher = os.urandom(AES_BLOCK_LEN)

        plain_module = b'\x00' * AES_BLOCK_LEN
        module[AES_KEY_LEN].AES_ECBDecrypt(key, cipher, plain_module)

        plain_reference = AES.new(key, AES.MODE_ECB).decrypt(cipher)

        self.assertEqual(plain_module, plain_reference)

class TestCBCEncrypt(unittest.TestCase):

  def testCBCEncryptZeros(self):
    for AES_KEY_LEN in (16, 24, 32):
      length = AES_BLOCK_LEN * 2
      key = b'\x00' * AES_KEY_LEN
      iv = b'\x00' * AES_BLOCK_LEN
      plain = b'\x00' * length

      cipher_module = b'\x00' * length
      module[AES_KEY_LEN].AES_CBCEncrypt(key, iv, plain, length, cipher_module)

      iv_ecb = AES.new(key, AES.MODE_ECB).encrypt(iv)
      cipher_reference = AES.new(key, AES.MODE_CBC, iv_ecb).encrypt(plain)

      self.assertEqual(cipher_module, cipher_reference)

  def testCBCEncryptRandom(self):
    for AES_KEY_LEN in (16, 24, 32):
      for count in range(1024):
        num = random.randint(0, 16)
        length = AES_BLOCK_LEN * num
        key = os.urandom(AES_KEY_LEN)
        iv = os.urandom(AES_BLOCK_LEN)
        plain = os.urandom(length)

        cipher_module = b'\x00' * length
        module[AES_KEY_LEN].AES_CBCEncrypt(key, iv, plain, length, cipher_module)

        iv_ecb = AES.new(key, AES.MODE_ECB).encrypt(iv)
        cipher_reference = AES.new(key, AES.MODE_CBC, iv_ecb).encrypt(plain)

        self.assertEqual(cipher_module, cipher_reference)

class TestCBCDecrypt(unittest.TestCase):

  def testCBCDecryptZeros(self):
    for AES_KEY_LEN in (16, 24, 32):
      length = AES_BLOCK_LEN * 2
      key = b'\x00' * AES_KEY_LEN
      iv = b'\x00' * AES_BLOCK_LEN
      cipher = b'\x00' * length

      plain_module = b'\x00' * length
      module[AES_KEY_LEN].AES_CBCDecrypt(key, iv, cipher, length, plain_module)

      iv_ecb = AES.new(key, AES.MODE_ECB).encrypt(iv)
      plain_reference = AES.new(key, AES.MODE_CBC, iv_ecb).decrypt(cipher)

      self.assertEqual(plain_module, plain_reference)

  def testCBCDecryptRandom(self):
    for AES_KEY_LEN in (16, 24, 32):
      for count in range(1024):
        num = random.randint(0, 16)
        length = AES_BLOCK_LEN * num
        key = os.urandom(AES_KEY_LEN)
        iv = os.urandom(AES_BLOCK_LEN)
        cipher = os.urandom(length)

        plain_module = b'\x00' * length
        module[AES_KEY_LEN].AES_CBCDecrypt(key, iv, cipher, length, plain_module)

        iv_ecb = AES.new(key, AES.MODE_ECB).encrypt(iv)
        plain_reference = AES.new(key, AES.MODE_CBC, iv_ecb).decrypt(cipher)

        self.assertEqual(plain_module, plain_reference)

if __name__ == '__main__':
  unittest.main()
