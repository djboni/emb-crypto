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

module_name = 'sha3_'

source_files = [
  '../source/sha3.c',
  '../source/keccak.c',
]

include_paths = [
  '../include',
]

compiler_options = [
  '-std=c90',
  '-pedantic',
  '-DKECCAK_WORD=8',
]

module, ffi = load(
    source_files, include_paths, compiler_options,
    module_name=module_name)

import hashlib

class TestSHA3_512(unittest.TestCase):

  def testSHA3_512Empty(self):
    HASH_BITS = 512
    length = 0
    data = b'\x00' * length
    hash_length = HASH_BITS // 8

    phash_ = ffi.new('struct sha3_512_t[1]')
    hash_ = phash_[0]

    module.SHA3_512Init(phash_)
    module.SHA3_512Update(phash_, data, length)
    module.SHA3_512Finish(phash_)

    hash_module = ffi.buffer(hash_.hash.a, hash_length)
    hash_module = hash_module[:]

    hash_reference = hashlib.sha3_512(data).digest()

    self.assertEqual(hash_module, hash_reference)

  def testSHA3_512Zero(self):
    HASH_BITS = 512
    length = 1
    data = b'\x00' * length
    hash_length = HASH_BITS // 8

    phash_ = ffi.new('struct sha3_512_t[1]')
    hash_ = phash_[0]

    module.SHA3_512Init(phash_)
    module.SHA3_512Update(phash_, data, length)
    module.SHA3_512Finish(phash_)

    hash_module = ffi.buffer(hash_.hash.a, hash_length)
    hash_module = hash_module[:]

    hash_reference = hashlib.sha3_512(data).digest()

    self.assertEqual(hash_module, hash_reference)

  def testSHA3_512Zeros(self):
    HASH_BITS = 512
    length = random.randint(0, 1024)
    data = b'\x00' * length
    hash_length = HASH_BITS // 8

    phash_ = ffi.new('struct sha3_512_t[1]')
    hash_ = phash_[0]

    module.SHA3_512Init(phash_)
    module.SHA3_512Update(phash_, data, length)
    module.SHA3_512Finish(phash_)

    hash_module = ffi.buffer(hash_.hash.a, hash_length)
    hash_module = hash_module[:]

    hash_reference = hashlib.sha3_512(data).digest()

    self.assertEqual(hash_module, hash_reference)

  def testSHA3_512Random(self):
    HASH_BITS = 512
    length = random.randint(0, 1024)
    data = os.urandom(length)
    hash_length = HASH_BITS // 8

    phash_ = ffi.new('struct sha3_512_t[1]')
    hash_ = phash_[0]

    module.SHA3_512Init(phash_)
    module.SHA3_512Update(phash_, data, length)
    module.SHA3_512Finish(phash_)

    hash_module = ffi.buffer(hash_.hash.a, hash_length)
    hash_module = hash_module[:]

    hash_reference = hashlib.sha3_512(data).digest()

    self.assertEqual(hash_module, hash_reference)

class TestSHA3_384(unittest.TestCase):

  def testSHA3_384Empty(self):
    HASH_BITS = 384
    length = 0
    data = b'\x00' * length
    hash_length = HASH_BITS // 8

    phash_ = ffi.new('struct sha3_384_t[1]')
    hash_ = phash_[0]

    module.SHA3_384Init(phash_)
    module.SHA3_384Update(phash_, data, length)
    module.SHA3_384Finish(phash_)

    hash_module = ffi.buffer(hash_.hash.a, hash_length)
    hash_module = hash_module[:]

    hash_reference = hashlib.sha3_384(data).digest()

    self.assertEqual(hash_module, hash_reference)

  def testSHA3_384Zero(self):
    HASH_BITS = 384
    length = 1
    data = b'\x00' * length
    hash_length = HASH_BITS // 8

    phash_ = ffi.new('struct sha3_384_t[1]')
    hash_ = phash_[0]

    module.SHA3_384Init(phash_)
    module.SHA3_384Update(phash_, data, length)
    module.SHA3_384Finish(phash_)

    hash_module = ffi.buffer(hash_.hash.a, hash_length)
    hash_module = hash_module[:]

    hash_reference = hashlib.sha3_384(data).digest()

    self.assertEqual(hash_module, hash_reference)

  def testSHA3_384Zeros(self):
    HASH_BITS = 384
    length = random.randint(0, 1024)
    data = b'\x00' * length
    hash_length = HASH_BITS // 8

    phash_ = ffi.new('struct sha3_384_t[1]')
    hash_ = phash_[0]

    module.SHA3_384Init(phash_)
    module.SHA3_384Update(phash_, data, length)
    module.SHA3_384Finish(phash_)

    hash_module = ffi.buffer(hash_.hash.a, hash_length)
    hash_module = hash_module[:]

    hash_reference = hashlib.sha3_384(data).digest()

    self.assertEqual(hash_module, hash_reference)

  def testSHA3_384Random(self):
    HASH_BITS = 384
    length = random.randint(0, 1024)
    data = os.urandom(length)
    hash_length = HASH_BITS // 8

    phash_ = ffi.new('struct sha3_384_t[1]')
    hash_ = phash_[0]

    module.SHA3_384Init(phash_)
    module.SHA3_384Update(phash_, data, length)
    module.SHA3_384Finish(phash_)

    hash_module = ffi.buffer(hash_.hash.a, hash_length)
    hash_module = hash_module[:]

    hash_reference = hashlib.sha3_384(data).digest()

    self.assertEqual(hash_module, hash_reference)

class TestSHA3_256(unittest.TestCase):

  def testSHA3_256Empty(self):
    HASH_BITS = 256
    length = 0
    data = b'\x00' * length
    hash_length = HASH_BITS // 8

    phash_ = ffi.new('struct sha3_256_t[1]')
    hash_ = phash_[0]

    module.SHA3_256Init(phash_)
    module.SHA3_256Update(phash_, data, length)
    module.SHA3_256Finish(phash_)

    hash_module = ffi.buffer(hash_.hash.a, hash_length)
    hash_module = hash_module[:]

    hash_reference = hashlib.sha3_256(data).digest()

    self.assertEqual(hash_module, hash_reference)

  def testSHA3_256Zero(self):
    HASH_BITS = 256
    length = 1
    data = b'\x00' * length
    hash_length = HASH_BITS // 8

    phash_ = ffi.new('struct sha3_256_t[1]')
    hash_ = phash_[0]

    module.SHA3_256Init(phash_)
    module.SHA3_256Update(phash_, data, length)
    module.SHA3_256Finish(phash_)

    hash_module = ffi.buffer(hash_.hash.a, hash_length)
    hash_module = hash_module[:]

    hash_reference = hashlib.sha3_256(data).digest()

    self.assertEqual(hash_module, hash_reference)

  def testSHA3_256Zeros(self):
    HASH_BITS = 256
    length = random.randint(0, 1024)
    data = b'\x00' * length
    hash_length = HASH_BITS // 8

    phash_ = ffi.new('struct sha3_256_t[1]')
    hash_ = phash_[0]

    module.SHA3_256Init(phash_)
    module.SHA3_256Update(phash_, data, length)
    module.SHA3_256Finish(phash_)

    hash_module = ffi.buffer(hash_.hash.a, hash_length)
    hash_module = hash_module[:]

    hash_reference = hashlib.sha3_256(data).digest()

    self.assertEqual(hash_module, hash_reference)

  def testSHA3_256Random(self):
    HASH_BITS = 256
    length = random.randint(0, 1024)
    data = os.urandom(length)
    hash_length = HASH_BITS // 8

    phash_ = ffi.new('struct sha3_256_t[1]')
    hash_ = phash_[0]

    module.SHA3_256Init(phash_)
    module.SHA3_256Update(phash_, data, length)
    module.SHA3_256Finish(phash_)

    hash_module = ffi.buffer(hash_.hash.a, hash_length)
    hash_module = hash_module[:]

    hash_reference = hashlib.sha3_256(data).digest()

    self.assertEqual(hash_module, hash_reference)

class TestSHA3_224(unittest.TestCase):

  def testSHA3_224Empty(self):
    HASH_BITS = 224
    length = 0
    data = b'\x00' * length
    hash_length = HASH_BITS // 8

    phash_ = ffi.new('struct sha3_224_t[1]')
    hash_ = phash_[0]

    module.SHA3_224Init(phash_)
    module.SHA3_224Update(phash_, data, length)
    module.SHA3_224Finish(phash_)

    hash_module = ffi.buffer(hash_.hash.a, hash_length)
    hash_module = hash_module[:]

    hash_reference = hashlib.sha3_224(data).digest()

    self.assertEqual(hash_module, hash_reference)

  def testSHA3_256Zero(self):
    HASH_BITS = 224
    length = 1
    data = b'\x00' * length
    hash_length = HASH_BITS // 8

    phash_ = ffi.new('struct sha3_224_t[1]')
    hash_ = phash_[0]

    module.SHA3_224Init(phash_)
    module.SHA3_224Update(phash_, data, length)
    module.SHA3_224Finish(phash_)

    hash_module = ffi.buffer(hash_.hash.a, hash_length)
    hash_module = hash_module[:]

    hash_reference = hashlib.sha3_224(data).digest()

    self.assertEqual(hash_module, hash_reference)

  def testSHA3_256Zeros(self):
    HASH_BITS = 224
    length = random.randint(0, 1024)
    data = b'\x00' * length
    hash_length = HASH_BITS // 8

    phash_ = ffi.new('struct sha3_224_t[1]')
    hash_ = phash_[0]

    module.SHA3_224Init(phash_)
    module.SHA3_224Update(phash_, data, length)
    module.SHA3_224Finish(phash_)

    hash_module = ffi.buffer(hash_.hash.a, hash_length)
    hash_module = hash_module[:]

    hash_reference = hashlib.sha3_224(data).digest()

    self.assertEqual(hash_module, hash_reference)

  def testSHA3_256Random(self):
    HASH_BITS = 224
    length = random.randint(0, 1024)
    data = os.urandom(length)
    hash_length = HASH_BITS // 8

    phash_ = ffi.new('struct sha3_224_t[1]')
    hash_ = phash_[0]

    module.SHA3_224Init(phash_)
    module.SHA3_224Update(phash_, data, length)
    module.SHA3_224Finish(phash_)

    hash_module = ffi.buffer(hash_.hash.a, hash_length)
    hash_module = hash_module[:]

    hash_reference = hashlib.sha3_224(data).digest()

    self.assertEqual(hash_module, hash_reference)

class TestSHAKE_256(unittest.TestCase):

  def testSHAKE_256Empty(self):
    HASH_BITS = 256
    length = 0
    data = b'\x00' * length
    hash_length = HASH_BITS // 8

    phash_ = ffi.new('struct shake_256_t[1]')
    hash_ = phash_[0]

    hash_module = b'\x00' * hash_length
    module.SHAKE256Init(phash_)
    module.SHAKE256Absorb(phash_, data, length)
    module.SHAKE256Finish(phash_)
    module.SHAKE256Squeeze(phash_, hash_module, hash_length)

    hash_reference = hashlib.shake_256(data).digest(hash_length)

    self.assertEqual(hash_module, hash_reference)

  def testSHAKE_256Zero(self):
    HASH_BITS = 256
    length = 1
    data = b'\x00' * length
    hash_length = HASH_BITS // 8

    phash_ = ffi.new('struct shake_256_t[1]')
    hash_ = phash_[0]

    hash_module = b'\x00' * hash_length
    module.SHAKE256Init(phash_)
    module.SHAKE256Absorb(phash_, data, length)
    module.SHAKE256Finish(phash_)
    module.SHAKE256Squeeze(phash_, hash_module, hash_length)

    hash_reference = hashlib.shake_256(data).digest(hash_length)

    self.assertEqual(hash_module, hash_reference)

  def testSHAKE_256Zeros(self):
    HASH_BITS = 256
    length = random.randint(0, 1024)
    data = b'\x00' * length
    hash_length = HASH_BITS // 8

    phash_ = ffi.new('struct shake_256_t[1]')
    hash_ = phash_[0]

    hash_module = b'\x00' * hash_length
    module.SHAKE256Init(phash_)
    module.SHAKE256Absorb(phash_, data, length)
    module.SHAKE256Finish(phash_)
    module.SHAKE256Squeeze(phash_, hash_module, hash_length)

    hash_reference = hashlib.shake_256(data).digest(hash_length)

    self.assertEqual(hash_module, hash_reference)

  def testSHAKE_256Random(self):
    HASH_BITS = 256
    length = random.randint(0, 1024)
    data = os.urandom(length)
    hash_length = HASH_BITS // 8

    phash_ = ffi.new('struct shake_256_t[1]')
    hash_ = phash_[0]

    hash_module = b'\x00' * hash_length
    module.SHAKE256Init(phash_)
    module.SHAKE256Absorb(phash_, data, length)
    module.SHAKE256Finish(phash_)
    module.SHAKE256Squeeze(phash_, hash_module, hash_length)

    hash_reference = hashlib.shake_256(data).digest(hash_length)

    self.assertEqual(hash_module, hash_reference)

class TestSHAKE_128(unittest.TestCase):

  def testSHAKE_128Empty(self):
    HASH_BITS = 128
    length = 0
    data = b'\x00' * length
    hash_length = HASH_BITS // 8

    phash_ = ffi.new('struct shake_128_t[1]')
    hash_ = phash_[0]

    hash_module = b'\x00' * hash_length
    module.SHAKE128Init(phash_)
    module.SHAKE128Absorb(phash_, data, length)
    module.SHAKE128Finish(phash_)
    module.SHAKE128Squeeze(phash_, hash_module, hash_length)

    hash_reference = hashlib.shake_128(data).digest(hash_length)

    self.assertEqual(hash_module, hash_reference)

  def testSHAKE_128Zero(self):
    HASH_BITS = 128
    length = 1
    data = b'\x00' * length
    hash_length = HASH_BITS // 8

    phash_ = ffi.new('struct shake_128_t[1]')
    hash_ = phash_[0]

    hash_module = b'\x00' * hash_length
    module.SHAKE128Init(phash_)
    module.SHAKE128Absorb(phash_, data, length)
    module.SHAKE128Finish(phash_)
    module.SHAKE128Squeeze(phash_, hash_module, hash_length)

    hash_reference = hashlib.shake_128(data).digest(hash_length)

    self.assertEqual(hash_module, hash_reference)

  def testSHAKE_128Zeros(self):
    HASH_BITS = 128
    length = random.randint(0, 1024)
    data = b'\x00' * length
    hash_length = HASH_BITS // 8

    phash_ = ffi.new('struct shake_128_t[1]')
    hash_ = phash_[0]

    hash_module = b'\x00' * hash_length
    module.SHAKE128Init(phash_)
    module.SHAKE128Absorb(phash_, data, length)
    module.SHAKE128Finish(phash_)
    module.SHAKE128Squeeze(phash_, hash_module, hash_length)

    hash_reference = hashlib.shake_128(data).digest(hash_length)

    self.assertEqual(hash_module, hash_reference)

  def testSHAKE_128Random(self):
    HASH_BITS = 128
    length = random.randint(0, 1024)
    data = os.urandom(length)
    hash_length = HASH_BITS // 8

    phash_ = ffi.new('struct shake_128_t[1]')
    hash_ = phash_[0]

    hash_module = b'\x00' * hash_length
    module.SHAKE128Init(phash_)
    module.SHAKE128Absorb(phash_, data, length)
    module.SHAKE128Finish(phash_)
    module.SHAKE128Squeeze(phash_, hash_module, hash_length)

    hash_reference = hashlib.shake_128(data).digest(hash_length)

    self.assertEqual(hash_module, hash_reference)

if __name__ == '__main__':
  unittest.main()
