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

void SHA1_digest(struct SHA1_t *state);

void SHA1_init(struct SHA1_t *state) {
  state->hash[0] = 0x67452301;
  state->hash[1] = 0xEFCDAB89;
  state->hash[2] = 0x98BADCFE;
  state->hash[3] = 0x10325476;
  state->hash[4] = 0xC3D2E1F0;

  state->num = 0;

#if 0
  {
    uint8_t i;
    for(i=0; i < 16; ++i)
      state->data[i] = 0xFFFFFFFF;
  }
#endif
}

void SHA1_update(struct SHA1_t *state, const void *data, uint16_t num) {
  const uint8_t *in = data;
  uint8_t *out = ((uint8_t *)&state->data) + (state->num % 64);

  while (num-- > 0) {
    *out++ = *in++;
    if (++(state->num) % 64 == 0) {
      /* Digest when a block is completed. */
      SHA1_digest(state);
      out = (uint8_t *)&state->data;
    }
  }
}

void SHA1_finish(struct SHA1_t *state) {
  uint8_t *data = (uint8_t *)&state->data;
  uint8_t i;
  uint64_t nbits = state->num * 8;

  /* PAD */
  i = state->num % 64;
  data[i++] = 0x80;
  if (i > 56) {
    for (; i < 64; ++i)
      data[i] = 0x00;
    SHA1_digest(state);
    i = 0;
  }
  for (; i < 56; ++i)
    data[i] = 0x00;

  /* Message length */

  /* Big endian. */
  /* *(uint64_t*)&data[56] = state->num * 8; */

  /* Little endian. */
  for (i = 0; i < 8; ++i) {
    data[63 - i] = nbits;
    nbits >>= 8;
  }

  SHA1_digest(state);
}

void SHA1_big_to_little_endian(struct SHA1_t *state) {
  uint8_t i;
  uint32_t val;

  for (i = 0; i < 5; ++i) {
    val = state->hash[i];
    val = (val >> 24) | ((val & 0x00FF0000) >> 8) | ((val & 0x0000FF00) << 8) |
          (val << 24);
    state->hash[i] = val;
  }
}

static uint32_t leftrotate1(uint32_t x) {
  const uint8_t n = 1;
  return ((x >> (32 - n)) | (x << n));
}

static uint32_t leftrotate5(uint32_t x) {
  const uint8_t n = 5;
  return ((x >> (32 - n)) | (x << n));
}

static uint32_t leftrotate30(uint32_t x) {
  const uint8_t n = 30;
  return ((x >> (32 - n)) | (x << n));
}

static uint32_t little_to_big(uint32_t x) {
  return ((x >> 24) & 0x000000FF) | ((x >> 8) & 0x0000FF00) |
         ((x << 8) & 0x00FF0000) | ((x << 24) & 0xFF000000);
}

void SHA1_digest(struct SHA1_t *state) {
  uint32_t a = state->hash[0];
  uint32_t b = state->hash[1];
  uint32_t c = state->hash[2];
  uint32_t d = state->hash[3];
  uint32_t e = state->hash[4];
  uint8_t i, j;
  uint32_t f, k, temp;

  /* Change from little to big endian */
  for (i = 0; i < 16; ++i)
    state->data[i] = little_to_big(state->data[i]);

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

    temp = leftrotate5(a) + f + e + k + state->data[0];
    e = d;
    d = c;
    c = leftrotate30(b);
    b = a;
    a = temp;

    temp = state->data[13] ^ state->data[8] ^ state->data[2] ^ state->data[0];
    temp = leftrotate1(temp);
    for (j = 0; j < 15; ++j)
      state->data[j] = state->data[j + 1];
    state->data[15] = temp;
  }

  state->hash[0] += a;
  state->hash[1] += b;
  state->hash[2] += c;
  state->hash[3] += d;
  state->hash[4] += e;
}
