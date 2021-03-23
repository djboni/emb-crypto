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

module, ffi = {}, {}

for HASH_BITS in (512, 384, 256, 224):

  module_name = 'sha3_%d_' % HASH_BITS

  source_files = [
    '../source/keccak.c',
    '../source/keccak_hash.c',
  ]

  include_paths = [
    '../include',
  ]

  compiler_options = [
    '-std=c90',
    '-pedantic',
    '-DKECCAK_WORD=8',
    '-DKECCAK_HASH_OUTPUT=%d' % (HASH_BITS / 8),
    '-DKECCAK_XOF_SECURITY=%d' % (HASH_BITS / 16),
  ]

  module[HASH_BITS], ffi[HASH_BITS] = load(
      source_files, include_paths, compiler_options,
      module_name=module_name)

import hashlib

sha3 = {
  512: hashlib.sha3_512,
  384: hashlib.sha3_384,
  256: hashlib.sha3_256,
  224: hashlib.sha3_224
}
shake = { 512: hashlib.shake_256, 256: hashlib.shake_128 }

class TestSHA3(unittest.TestCase):

  def testSHA3Empty(self):
    for HASH_BITS in (512, 384, 256, 224):
      length = 0
      data = b'\x00' * length
      hash_length = HASH_BITS // 8

      phash_ = ffi[HASH_BITS].new('struct KECCAK_HASH_t[1]')
      hash_ = phash_[0]

      module[HASH_BITS].KECCAK_HASH_init(phash_)
      module[HASH_BITS].KECCAK_HASH_update(phash_, data, length)
      module[HASH_BITS].KECCAK_HASH_finish(phash_)

      hash_module = ffi[HASH_BITS].buffer(hash_.state.A, hash_length)
      hash_module = hash_module[:]

      hash_reference = sha3[HASH_BITS](data).digest()

      self.assertEqual(hash_module, hash_reference)

  def testSHA3Zero(self):
    for HASH_BITS in (512, 384, 256, 224):
      length = 1
      data = b'\x00' * length
      hash_length = HASH_BITS // 8

      phash_ = ffi[HASH_BITS].new('struct KECCAK_HASH_t[1]')
      hash_ = phash_[0]

      module[HASH_BITS].KECCAK_HASH_init(phash_)
      module[HASH_BITS].KECCAK_HASH_update(phash_, data, length)
      module[HASH_BITS].KECCAK_HASH_finish(phash_)

      hash_module = ffi[HASH_BITS].buffer(hash_.state.A, hash_length)
      hash_module = hash_module[:]

      hash_reference = sha3[HASH_BITS](data).digest()

      self.assertEqual(hash_module, hash_reference)

  def testSHA3Zeros(self):
    for HASH_BITS in (512, 384, 256, 224):
      length = random.randint(0, 1024)
      data = b'\x00' * length
      hash_length = HASH_BITS // 8

      phash_ = ffi[HASH_BITS].new('struct KECCAK_HASH_t[1]')
      hash_ = phash_[0]

      module[HASH_BITS].KECCAK_HASH_init(phash_)
      module[HASH_BITS].KECCAK_HASH_update(phash_, data, length)
      module[HASH_BITS].KECCAK_HASH_finish(phash_)

      hash_module = ffi[HASH_BITS].buffer(hash_.state.A, hash_length)
      hash_module = hash_module[:]

      hash_reference = sha3[HASH_BITS](data).digest()

      self.assertEqual(hash_module, hash_reference)

  def testSHA3Random(self):
    for HASH_BITS in (512, 384, 256, 224):
      length = random.randint(0, 1024)
      data = os.urandom(length)
      hash_length = HASH_BITS // 8

      phash_ = ffi[HASH_BITS].new('struct KECCAK_HASH_t[1]')
      hash_ = phash_[0]

      module[HASH_BITS].KECCAK_HASH_init(phash_)
      module[HASH_BITS].KECCAK_HASH_update(phash_, data, length)
      module[HASH_BITS].KECCAK_HASH_finish(phash_)

      hash_module = ffi[HASH_BITS].buffer(hash_.state.A, hash_length)
      hash_module = hash_module[:]

      hash_reference = sha3[HASH_BITS](data).digest()

      self.assertEqual(hash_module, hash_reference)

class TestSHAKE(unittest.TestCase):

  def testSHAKEEmpty(self):
    for HASH_BITS in (512, 256):
      length = 0
      data = b'\x00' * length
      xof_length = HASH_BITS // 8

      pxof = ffi[HASH_BITS].new('struct KECCAK_XOF_t[1]')

      module[HASH_BITS].KECCAK_XOF_init(pxof)
      module[HASH_BITS].KECCAK_XOF_absorb(pxof, data, length)
      module[HASH_BITS].KECCAK_XOF_finish(pxof)

      xof_module = b'\x00' * xof_length
      module[HASH_BITS].KECCAK_XOF_squeeze(pxof, xof_module, xof_length)

      xof_reference = shake[HASH_BITS](data).digest(xof_length)

      self.assertEqual(xof_module, xof_reference)

  def testSHAKEZero(self):
    for HASH_BITS in (512, 256):
      length = 1
      data = b'\x00' * length
      xof_length = HASH_BITS // 8

      pxof = ffi[HASH_BITS].new('struct KECCAK_XOF_t[1]')

      module[HASH_BITS].KECCAK_XOF_init(pxof)
      module[HASH_BITS].KECCAK_XOF_absorb(pxof, data, length)
      module[HASH_BITS].KECCAK_XOF_finish(pxof)

      xof_module = b'\x00' * xof_length
      module[HASH_BITS].KECCAK_XOF_squeeze(pxof, xof_module, xof_length)

      xof_reference = shake[HASH_BITS](data).digest(xof_length)

      self.assertEqual(xof_module, xof_reference)

  def testSHAKEZeros(self):
    for HASH_BITS in (512, 256):
      length = random.randint(0, 1024)
      data = b'\x00' * length
      xof_length = HASH_BITS // 8

      pxof = ffi[HASH_BITS].new('struct KECCAK_XOF_t[1]')

      module[HASH_BITS].KECCAK_XOF_init(pxof)
      module[HASH_BITS].KECCAK_XOF_absorb(pxof, data, length)
      module[HASH_BITS].KECCAK_XOF_finish(pxof)

      xof_module = b'\x00' * xof_length
      module[HASH_BITS].KECCAK_XOF_squeeze(pxof, xof_module, xof_length)

      xof_reference = shake[HASH_BITS](data).digest(xof_length)

      self.assertEqual(xof_module, xof_reference)

  def testSHAKERandom(self):
    for HASH_BITS in (512, 256):
      length = random.randint(0, 1024)
      data = os.urandom(length)
      xof_length = HASH_BITS // 8

      pxof = ffi[HASH_BITS].new('struct KECCAK_XOF_t[1]')

      module[HASH_BITS].KECCAK_XOF_init(pxof)
      module[HASH_BITS].KECCAK_XOF_absorb(pxof, data, length)
      module[HASH_BITS].KECCAK_XOF_finish(pxof)

      xof_module = b'\x00' * xof_length
      module[HASH_BITS].KECCAK_XOF_squeeze(pxof, xof_module, xof_length)

      xof_reference = shake[HASH_BITS](data).digest(xof_length)

      self.assertEqual(xof_module, xof_reference)

if __name__ == '__main__':
  unittest.main()
