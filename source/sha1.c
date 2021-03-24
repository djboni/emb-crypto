/*
 SHA1 implementation.

 Copyright 2021 Djones A. Boni

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

#include "sha1.h"

void SHA1Digest(struct sha1_t *state_ptr);

void SHA1Init(struct sha1_t *state_ptr) {
  state_ptr->hash[0] = 0x67452301;
  state_ptr->hash[1] = 0xEFCDAB89;
  state_ptr->hash[2] = 0x98BADCFE;
  state_ptr->hash[3] = 0x10325476;
  state_ptr->hash[4] = 0xC3D2E1F0;

  state_ptr->num = 0;

#if 0
  {
    uint8_t i;
    for(i=0; i < 16; ++i)
      state_ptr->data[i] = 0xFFFFFFFF;
  }
#endif
}

void SHA1Update(struct sha1_t *state_ptr, const void *data_ptr, uint16_t num) {
  const uint8_t *in_ptr = data_ptr;
  uint8_t *out_ptr = ((uint8_t *)&state_ptr->data) + (state_ptr->num % 64);

  while (num-- > 0) {
    *out_ptr++ = *in_ptr++;
    if (++(state_ptr->num) % 64 == 0) {
      /* Digest when a block is completed. */
      SHA1Digest(state_ptr);
      out_ptr = (uint8_t *)&state_ptr->data;
    }
  }
}

void SHA1Finish(struct sha1_t *state_ptr) {
  uint8_t *data_ptr = (uint8_t *)&state_ptr->data;
  uint8_t i;
  uint64_t nbits = state_ptr->num * 8;

  /* PAD */
  i = state_ptr->num % 64;
  data_ptr[i++] = 0x80;
  if (i > 56) {
    for (; i < 64; ++i)
      data_ptr[i] = 0x00;
    SHA1Digest(state_ptr);
    i = 0;
  }
  for (; i < 56; ++i)
    data_ptr[i] = 0x00;

  /* Message length */

  /* Big endian. */
  /* *(uint64_t*)&data_ptr[56] = state_ptr->num * 8; */

  /* Little endian. */
  for (i = 0; i < 8; ++i) {
    data_ptr[63 - i] = nbits;
    nbits >>= 8;
  }

  SHA1Digest(state_ptr);
}

static uint32_t LittleToBig(uint32_t x) {
  return ((x >> 24) & 0x000000FF) | ((x >> 8) & 0x0000FF00) |
         ((x << 8) & 0x00FF0000) | ((x << 24) & 0xFF000000);
}

void SHA1BigToLittleEndian(struct sha1_t *state_ptr) {
  uint8_t i;

  for (i = 0; i < 5; ++i) {
    state_ptr->hash[i] = LittleToBig(state_ptr->hash[i]);
  }
}

static uint32_t LeftRotate1(uint32_t x) {
  const uint8_t n = 1;
  return ((x >> (32 - n)) | (x << n));
}

static uint32_t LeftRotate5(uint32_t x) {
  const uint8_t n = 5;
  return ((x >> (32 - n)) | (x << n));
}

static uint32_t LeftRotate30(uint32_t x) {
  const uint8_t n = 30;
  return ((x >> (32 - n)) | (x << n));
}

void SHA1Digest(struct sha1_t *state_ptr) {
  uint32_t a = state_ptr->hash[0];
  uint32_t b = state_ptr->hash[1];
  uint32_t c = state_ptr->hash[2];
  uint32_t d = state_ptr->hash[3];
  uint32_t e = state_ptr->hash[4];
  uint8_t i, j;
  uint32_t f, k, temp;

  /* Change from little to big endian */
  for (i = 0; i < 16; ++i)
    state_ptr->data[i] = LittleToBig(state_ptr->data[i]);

  for (i = 0; i < 80; ++i) {
    if (i < 20) {
      f = (b & c) | ((~b) & d);
      k = 0x5A827999;
    } else if (i < 40) {
      f = b ^ c ^ d;
      k = 0x6ED9EBA1;
    } else if (i < 60) {
      f = (b & c) | (b & d) | (c & d);
      k = 0x8F1BBCDC;
    } else {
      f = b ^ c ^ d;
      k = 0xCA62C1D6;
    }

    temp = LeftRotate5(a) + f + e + k + state_ptr->data[0];
    e = d;
    d = c;
    c = LeftRotate30(b);
    b = a;
    a = temp;

    temp = state_ptr->data[13] ^ state_ptr->data[8] ^ state_ptr->data[2] ^
           state_ptr->data[0];
    temp = LeftRotate1(temp);
    for (j = 0; j < 15; ++j)
      state_ptr->data[j] = state_ptr->data[j + 1];
    state_ptr->data[15] = temp;
  }

  state_ptr->hash[0] += a;
  state_ptr->hash[1] += b;
  state_ptr->hash[2] += c;
  state_ptr->hash[3] += d;
  state_ptr->hash[4] += e;
}
