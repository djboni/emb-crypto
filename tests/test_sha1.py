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

HASH_BITS = 160

module_name = 'sha1_'

source_files = [
  '../source/sha1.c',
]

include_paths = [
  '../include',
]

compiler_options = [
  '-std=c90',
  '-pedantic',
]

module, ffi = load(
    source_files, include_paths, compiler_options,
    module_name=module_name)

import hashlib

class TestSHA1(unittest.TestCase):

  def testSHA1Empty(self):
    length = 0
    data = b'\x00' * length
    hash_length = HASH_BITS // 8

    phash_ = ffi.new('struct sha1_t[1]')
    hash_ = phash_[0]

    module.SHA1Init(phash_)
    module.SHA1Update(phash_, data, length)
    module.SHA1Finish(phash_)
    module.SHA1BigToLittleEndian(phash_)

    hash_module = ffi.buffer(hash_.hash, hash_length)
    hash_module = hash_module[:]

    hash_reference = hashlib.sha1(data).digest()

    self.assertEqual(hash_module, hash_reference)

  def testSHA1Zero(self):
    length = 1
    data = b'\x00' * length
    hash_length = HASH_BITS // 8

    phash_ = ffi.new('struct sha1_t[1]')
    hash_ = phash_[0]

    module.SHA1Init(phash_)
    module.SHA1Update(phash_, data, length)
    module.SHA1Finish(phash_)
    module.SHA1BigToLittleEndian(phash_)

    hash_module = ffi.buffer(hash_.hash, hash_length)
    hash_module = hash_module[:]

    hash_reference = hashlib.sha1(data).digest()

    self.assertEqual(hash_module, hash_reference)

  def testSHA1Zeros(self):
    length = random.randint(0, 1024)
    data = b'\x00' * length
    hash_length = HASH_BITS // 8

    phash_ = ffi.new('struct sha1_t[1]')
    hash_ = phash_[0]

    module.SHA1Init(phash_)
    module.SHA1Update(phash_, data, length)
    module.SHA1Finish(phash_)
    module.SHA1BigToLittleEndian(phash_)

    hash_module = ffi.buffer(hash_.hash, hash_length)
    hash_module = hash_module[:]

    hash_reference = hashlib.sha1(data).digest()

    self.assertEqual(hash_module, hash_reference)

  def testSHA1Random(self):
    for count in range(1024):
      length = random.randint(0, 1024)
      data = os.urandom(length)
      hash_length = HASH_BITS // 8

      phash_ = ffi.new('struct sha1_t[1]')
      hash_ = phash_[0]

      module.SHA1Init(phash_)
      module.SHA1Update(phash_, data, length)
      module.SHA1Finish(phash_)
      module.SHA1BigToLittleEndian(phash_)

      hash_module = ffi.buffer(hash_.hash, hash_length)
      hash_module = hash_module[:]

      hash_reference = hashlib.sha1(data).digest()

      self.assertEqual(hash_module, hash_reference)

if __name__ == '__main__':
  unittest.main()
