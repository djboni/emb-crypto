/*
 AES implementation.

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

#include "aes.h"
#include <stddef.h>

#ifdef AVR
#include <avr/pgmspace.h>
#else
#undef PROGMEM
#define PROGMEM
#undef pgm_read_byte
#define pgm_read_byte(x) *(x)
#endif

struct aes_subkey {
  uint8_t byte[AES_KEY_LEN];
  uint8_t i;
};

PROGMEM const uint8_t aes_bytesub_table[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

PROGMEM const uint8_t aes_invbytesub_table[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d};

PROGMEM const uint8_t aes_rcon_poli_table[10] = {0x01, 0x02, 0x04, 0x08, 0x10,
                                                 0x20, 0x40, 0x80, 0x1b, 0x36};

/* Value to XOR from least significant byte for most significant byte with
 * values 0-7 MSB(0x7FF == (0x80<<4)-1).
 * x^8 + x^4 + x^3 + x + 1 = 0x011b
 */
PROGMEM const uint8_t aes_mixcolumn_gf2p8_table[8] = {0x00, 0x1b, 0x36, 0x2d,
                                                      0x6c, 0x77, 0x5a, 0x41};

uint8_t aes_bytesub(uint8_t i) { return pgm_read_byte(&aes_bytesub_table[i]); }

uint8_t aes_invbytesub(uint8_t i) {
  return pgm_read_byte(&aes_invbytesub_table[i]);
}

uint8_t aes_rcon_poli(uint8_t i) {
  return pgm_read_byte(&aes_rcon_poli_table[i]);
}

uint8_t aes_mixcolumn_gf2p8(uint8_t i) {
  return pgm_read_byte(&aes_mixcolumn_gf2p8_table[i]);
}

void aes_subword(uint8_t bytes[4]) {
  uint8_t i;
  for (i = 0; i < 4; ++i)
    bytes[i] = aes_bytesub(bytes[i]);
}

void aes_rotword(uint8_t bytes[4]) {
  uint8_t i;
  uint8_t temp[4];
  for (i = 0; i < 4; ++i)
    temp[i] = bytes[i];
  for (i = 0; i < 4; ++i)
    bytes[i] = temp[(i + 1) % 4];
}

void aes_rcon(uint8_t bytes[4], uint8_t i) { bytes[0] ^= aes_rcon_poli(i); }

uint8_t mod_AES_KEY_LEN(uint8_t x) {
#if AES_KEY_LEN == 16
  return x % AES_KEY_LEN;
#elif AES_KEY_LEN == 32
  return x % AES_KEY_LEN;
#elif AES_KEY_LEN == 24
  /* return x % AES_KEY_LEN; */
  if (x >= 192)
    x -= 192;
  if (x >= 96)
    x -= 96;
  if (x >= 48)
    x -= 48;
  if (x >= 24)
    x -= 24;
  return x;
#endif
}

uint8_t mod_AES_KEY_LEN_4(uint8_t x) {
#if AES_KEY_LEN == 16
  return x % (AES_KEY_LEN / 4);
#elif AES_KEY_LEN == 32
  return x % (AES_KEY_LEN / 4);
#elif AES_KEY_LEN == 24
  /* return x % (AES_KEY_LEN / 4); */
  if (x >= 192)
    x -= 192;
  if (x >= 96)
    x -= 96;
  if (x >= 48)
    x -= 48;
  if (x >= 24)
    x -= 24;
  if (x >= 12)
    x -= 12;
  if (x >= 6)
    x -= 6;
  return x;
#endif
}

uint8_t div_AES_KEY_LEN_4(uint8_t x) {
#if AES_KEY_LEN == 16
  return x / (AES_KEY_LEN / 4);
#elif AES_KEY_LEN == 32
  return x / (AES_KEY_LEN / 4);
#elif AES_KEY_LEN == 24
  /* return x / (AES_KEY_LEN / 4); */
  uint8_t y = 0;
  if (x >= 192) {
    x -= 192;
    y += 32;
  }
  if (x >= 96) {
    x -= 96;
    y += 16;
  }
  if (x >= 48) {
    x -= 48;
    y += 8;
  }
  if (x >= 24) {
    x -= 24;
    y += 4;
  }
  if (x >= 12) {
    x -= 12;
    y += 2;
  }
  if (x >= 6) {
    x -= 6;
    y += 1;
  }
  return y;
#endif
}

void aes_key_expansion_internal(struct aes_subkey *subkey) {
  uint8_t temp[4], j;
  const uint8_t i = subkey->i;

  for (j = 0; j < 4; ++j) {
    temp[j] = subkey->byte[mod_AES_KEY_LEN(4 * i + (AES_KEY_LEN - 4) + j)];
  }

  if (mod_AES_KEY_LEN_4(i) == 0) {
    aes_rotword(temp);
    aes_subword(temp);
    aes_rcon(temp, (uint8_t)(div_AES_KEY_LEN_4(i) - 1));
  } else if ((AES_KEY_LEN / 4) > 6 && mod_AES_KEY_LEN_4(i) == 4) {
    aes_subword(temp);
  }

  for (j = 0; j < 4; ++j) {
    subkey->byte[mod_AES_KEY_LEN(4 * i + j)] =
        subkey->byte[mod_AES_KEY_LEN(4 * i + j)] ^ temp[j];
  }
}

void aes_key_expansion(struct aes_subkey *subkey, uint8_t round) {
  uint8_t i;
  if (round == 0) {
    subkey->i = AES_KEY_LEN / 4;
  } else {
    for (i = 0; i < 4; ++i) {
      if (subkey->i >= 4 * (AES_NUM_ROUNDS + 1)) {
        break;
      }
      aes_key_expansion_internal(subkey);
      subkey->i = (uint8_t)(subkey->i + 1);
    }
  }
}

void aes_inv_key_expansion(struct aes_subkey *subkey, uint8_t round) {
  uint8_t i;
  if (round == 0) {
  } else {
    if (round == AES_NUM_ROUNDS) {
      subkey->i = 4 * (AES_NUM_ROUNDS + 1);
    }

    for (i = 0; i < 4; ++i) {
      if (subkey->i == 0) {
        break;
      }
      subkey->i = (uint8_t)(subkey->i - 1);
      aes_key_expansion_internal(subkey);
    }
  }
}

void aes_mixcolumn(uint8_t col[4]) {
  uint16_t mixed[4] = {0, 0, 0, 0};
  const uint16_t fixed = col[0] ^ col[1] ^ col[2] ^ col[3];
  uint8_t i, j;

  for (i = 0; i < 4; ++i) {
    mixed[i] = fixed;

    for (j = 0; j < 4; ++j) {
      uint8_t k = (j - i) & 0x03; /* (j - i) % 4 */
      switch (k) {
      case 0:
        /* {02} x*col */
        mixed[i] = (uint16_t)(mixed[i] ^ col[j] ^ ((uint16_t)col[j] << 1));
        break;
      case 1:
        /* {03} x*col + col */
        mixed[i] = (uint16_t)(mixed[i] ^ ((uint16_t)col[j] << 1));
        break;
      default:
        /* {01} col */
        break;
      }
    }
  }

  for (i = 0; i < 4; ++i) {
    uint8_t msb = (uint8_t)(mixed[i] >> 8);
    uint8_t lsb = (uint8_t)(mixed[i]);
    col[i] = (uint8_t)(lsb ^ aes_mixcolumn_gf2p8(msb));
  }
}

void aes_invmixcolumn(uint8_t col[4]) {
  uint16_t mixed[4] = {0, 0, 0, 0};
  const uint16_t fixed =
      (uint16_t)(col[0] ^ col[1] ^ col[2] ^ col[3] ^ ((uint16_t)col[0] << 3) ^
                 ((uint16_t)col[1] << 3) ^ ((uint16_t)col[2] << 3) ^
                 ((uint16_t)col[3] << 3));
  uint8_t i, j;

  for (i = 0; i < 4; ++i) {
    mixed[i] = fixed;

    for (j = 0; j < 4; ++j) {
      uint8_t k = (j - i) & 0x03; /* (j - i) % 4 */
      switch (k) {
      case 0:
        /* {0e} x^3*col + x^2*col + x*col */
        mixed[i] = (uint16_t)(mixed[i] ^ col[j] ^ ((uint16_t)col[j] << 1) ^
                              ((uint16_t)col[j] << 2));
        break;
      case 1:
        /* {0b} x^3*col + x*col + col */
        mixed[i] = (uint16_t)(mixed[i] ^ ((uint16_t)col[j] << 1));
        break;
      case 2:
        /* {0d} x^3*col + x^2*col + col */
        mixed[i] = (uint16_t)(mixed[i] ^ ((uint16_t)col[j] << 2));
        break;
      default:
        /* {09} x^3*col + col */
        break;
      }
    }
  }

  for (i = 0; i < 4; ++i) {
    uint8_t msb = (uint8_t)(mixed[i] >> 8);
    uint8_t lsb = (uint8_t)(mixed[i]);
    col[i] = (uint8_t)(lsb ^ aes_mixcolumn_gf2p8(msb));
  }
}

void aes_byte_sub(uint8_t A[AES_BLOCK_LEN]) {
  uint8_t i;
  for (i = 0; i < AES_BLOCK_LEN; ++i) {
    A[i] = aes_bytesub(A[i]);
  }
}

void aes_shift_row(uint8_t A[AES_BLOCK_LEN]) {
  uint8_t T;

  /* B[0] = A[0]; */
  /* B[4] = A[4]; */
  /* B[8] = A[8]; */
  /* B[12] = A[12]; */

  /* B[1] = A[5]; */
  /* B[5] = A[9]; */
  /* B[9] = A[13]; */
  /* B[13] = A[1]; */
  T = A[1];
  A[1] = A[5];
  A[5] = A[9];
  A[9] = A[13];
  A[13] = T;

  /* B[2] = A[10]; */
  /* B[10] = A[2]; */
  /* B[6] = A[14]; */
  /* B[14] = A[6]; */
  T = A[2];
  A[2] = A[10];
  A[10] = T;
  T = A[6];
  A[6] = A[14];
  A[14] = T;

  /* B[3] = A[15]; */
  /* B[15] = A[11]; */
  /* B[11] = A[7]; */
  /* B[7] = A[3]; */
  T = A[3];
  A[3] = A[15];
  A[15] = A[11];
  A[11] = A[7];
  A[7] = T;
}

void aes_mix_col(uint8_t A[AES_BLOCK_LEN]) {
  aes_mixcolumn(&A[0]);
  aes_mixcolumn(&A[4]);
  aes_mixcolumn(&A[8]);
  aes_mixcolumn(&A[12]);
}

void aes_key_add(uint8_t A[AES_BLOCK_LEN], struct aes_subkey *subkey,
                 uint8_t round) {
  uint8_t i;
  aes_key_expansion(subkey, round);
  for (i = 0; i < AES_BLOCK_LEN; ++i) {
    A[i] = A[i] ^ subkey->byte[mod_AES_KEY_LEN(16 * round + i)];
  }
}

void aes_inv_byte_sub(uint8_t A[AES_BLOCK_LEN]) {
  uint8_t i;
  for (i = 0; i < AES_BLOCK_LEN; ++i) {
    A[i] = aes_invbytesub(A[i]);
  }
}

void aes_inv_shift_row(uint8_t A[AES_BLOCK_LEN]) {
  uint8_t T;

  /* B[0] = A[0]; */
  /* B[4] = A[4]; */
  /* B[8] = A[8]; */
  /* B[12] = A[12]; */

  /* B[1] = A[13]; */
  /* B[13] = A[9]; */
  /* B[9] = A[5]; */
  /* B[5] = A[1]; */
  T = A[1];
  A[1] = A[13];
  A[13] = A[9];
  A[9] = A[5];
  A[5] = T;

  /* B[2] = A[10]; */
  /* B[10] = A[2]; */
  /* B[6] = A[14]; */
  /* B[14] = A[6]; */
  T = A[2];
  A[2] = A[10];
  A[10] = T;
  T = A[6];
  A[6] = A[14];
  A[14] = T;

  /* B[3] = A[7]; */
  /* B[7] = A[11]; */
  /* B[11] = A[15]; */
  /* B[15] = A[3]; */
  T = A[3];
  A[3] = A[7];
  A[7] = A[11];
  A[11] = A[15];
  A[15] = T;
}

void aes_inv_mix_col(uint8_t A[AES_BLOCK_LEN]) {
  aes_invmixcolumn(&A[0]);
  aes_invmixcolumn(&A[4]);
  aes_invmixcolumn(&A[8]);
  aes_invmixcolumn(&A[12]);
}

void aes_inv_key_add(uint8_t A[AES_BLOCK_LEN], struct aes_subkey *subkey,
                     uint8_t round) {
  uint8_t i;
  for (i = 0; i < AES_BLOCK_LEN; ++i) {
    A[i] = A[i] ^ subkey->byte[mod_AES_KEY_LEN(16 * round + i)];
  }
  aes_inv_key_expansion(subkey, round);
}

/** AES encrypt
 *
 * Encrypts plain-text 'plain' with 'key', outputs cipher-text
 * to 'cipher'.
 */
void aes_ecb_encrypt(const uint8_t key[AES_KEY_LEN],
                     const uint8_t plain[AES_BLOCK_LEN],
                     uint8_t cipher[AES_BLOCK_LEN]) {
  uint8_t round;
  uint8_t A[AES_BLOCK_LEN];
  struct aes_subkey subkey;
  uint8_t i;

  /* Copy key to subkey */
  for (i = 0; i < AES_KEY_LEN; ++i) {
    subkey.byte[i] = key[i];
  }

  /* Copy plain-text to temporary variables */
  for (i = 0; i < AES_BLOCK_LEN; ++i) {
    A[i] = plain[i];
  }

  /* Rounds */
  for (round = 0; round < AES_NUM_ROUNDS; ++round) {
    aes_key_add(&A[0], &subkey, round);
    aes_byte_sub(&A[0]);
    aes_shift_row(&A[0]);
    if (round < AES_NUM_ROUNDS - 1)
      aes_mix_col(&A[0]);
  }
  aes_key_add(&A[0], &subkey, round);

  /* Copy cipher-text to output variable */
  for (i = 0; i < AES_BLOCK_LEN; ++i) {
    cipher[i] = A[i];
  }
}

/** AES key decryption expansion
 *
 * Expand the key for decryption, i.e. create a "decryption key".
 */
void aes_key_decrypt_expansion(uint8_t decrypt_key[AES_KEY_LEN],
                               const uint8_t key[AES_KEY_LEN]) {
  struct aes_subkey subkey;
  uint8_t i;

  /* Copy key to subkey */
  for (i = 0; i < AES_KEY_LEN; ++i) {
    subkey.byte[i] = key[i];
  }

  /* Run key expansion AES_NUM_ROUNDS+1 times */
  for (i = 0; i < AES_NUM_ROUNDS + 1; ++i) {
    aes_key_expansion(&subkey, i);
  }

  /* Copy expanded key to decryption key */
  for (i = 0; i < AES_KEY_LEN; ++i) {
    decrypt_key[i] = subkey.byte[i];
  }
}

/** AES decrypt
 *
 * Decrypts cipher-text 'cipher' with 'key', outputs plain-text
 * to 'plain'.
 */
void aes_ecb_decrypt(const uint8_t key[AES_KEY_LEN],
                     const uint8_t cipher[AES_BLOCK_LEN],
                     uint8_t plain[AES_BLOCK_LEN]) {
  uint8_t round;
  uint8_t A[AES_BLOCK_LEN];
  struct aes_subkey subkey;
  uint8_t i;

  /* Converto do decryption key, into subkey */
  aes_key_decrypt_expansion(&subkey.byte[0], key);

  /* Copy cipher-text to temporary variables */
  for (i = 0; i < AES_BLOCK_LEN; ++i) {
    A[i] = cipher[i];
  }

  /* Rounds */
  for (round = AES_NUM_ROUNDS; round > 0; --round) {
    aes_inv_key_add(&A[0], &subkey, round);
    if (round < AES_NUM_ROUNDS) {
      aes_inv_mix_col(&A[0]);
    }
    aes_inv_shift_row(&A[0]);
    aes_inv_byte_sub(&A[0]);
  }
  aes_inv_key_add(&A[0], &subkey, round);

  /* Copy plain-text to output variable */
  for (i = AES_BLOCK_LEN; i > 0; --i) {
    plain[i - 1] = A[i - 1];
  }
}

/** AES CBC encrypt
 *
 * Encrypts the plain-text 'plain' of size 'length' bytes with 'key'
 * and initialization vector 'iv', outputs cipher-text to 'cipher'.
 *
 * Note: Encryption and decryption must use the same initialization vector.
 * The initialization vector should be a nonce (number used once with the key).
 * It is not a secret and can be transmitted in plain-text.
 */
void aes_cbc_encrypt(const uint8_t key[AES_KEY_LEN],
                     const uint8_t iv[AES_BLOCK_LEN], const uint8_t *plain,
                     uint32_t length, uint8_t *cipher) {
  uint8_t A[AES_BLOCK_LEN];
  uint8_t i;

  /* A = C[0] = Ek(iv) */
  for (i = 0; i < AES_BLOCK_LEN; ++i) {
    A[i] = iv[i];
  }
  aes_ecb_encrypt(key, A, A);

  while (length > 0) {
    /* A = C[i] = Ek(P[i] ^ C[i-1] */
    for (i = 0; i < AES_BLOCK_LEN; ++i) {
      A[i] ^= *plain++;
    }
    length -= AES_BLOCK_LEN;
    aes_ecb_encrypt(key, A, A);

    /* cipher = A = C[i] */
    for (i = 0; i < AES_BLOCK_LEN; ++i) {
      *cipher++ = A[i];
    }
  }
}

/** AES CBC decrypt
 *
 * Decrypts the cipher-text 'cipher' of size 'length' bytes with 'key'
 * and initialization vector 'iv', outputs plain-text to 'plain'.
 *
 * Note: Encryption and decryption must use the same initialization vector.
 * The initialization vector should be a nonce (number used once with the key).
 * It is not a secret and can be transmitted in plain-text.
 */
void aes_cbc_decrypt(const uint8_t key[AES_KEY_LEN],
                     const uint8_t iv[AES_BLOCK_LEN], const uint8_t *cipher,
                     uint32_t length, uint8_t *plain) {
  uint8_t A[AES_BLOCK_LEN];
  uint8_t B[AES_BLOCK_LEN];
  uint8_t i;

  /* A = C[0] = Ek(iv) */
  for (i = 0; i < AES_BLOCK_LEN; ++i) {
    A[i] = iv[i];
  }
  aes_ecb_encrypt(key, A, A);

  while (length > 0) {
    /* B = Dk(C[i]) */
    for (i = 0; i < AES_BLOCK_LEN; ++i) {
      B[i] = cipher[i];
    }
    length -= AES_BLOCK_LEN;
    aes_ecb_decrypt(key, B, B);

    /* plain = P[i] = Dk(C[i]) XOR C[i-1] */
    /* A = C[i] */
    for (i = 0; i < AES_BLOCK_LEN; ++i) {
      *plain++ = B[i] ^ A[i];
      A[i] = *cipher++;
    }
  }
}

/* AES HASH.
 *
 * Length padding.
 * Merkle-Damgard construction: Length extension attack is possible.
 *
 * If you want to be REALLY SURE your EEPROM data is not corrupted, this makes
 * a very strong CRC. Much slower than a normal CRC though.
 *
 * If you want a MAC (message authentication code) on serial that is strong
 * against replay attacks, use a NONCE initialization vector (number used only
 * once, random or incremental) and encrypt the hash with the MAC key.
 * This way there is no length extension attack and no replay attack.
 *
 * struct aes_hash_state state;
 * aes_hash_init(&state);
 * aes_hash_update(&state, data1, length1);
 * aes_hash_update(&state, data2, length2);
 * // ... as much as you want
 * aes_hash_finish(&state);
 * // Hash in state.hash
 *
 */

void aes_hash_init(struct aes_hash_state *state) {
  uint8_t i;
  for (i = 0; i < AES_BLOCK_LEN; ++i)
    state->hash[i] = 0x00;
  state->length = 0;
}

void aes_hash_init_iv(struct aes_hash_state *state,
                      const uint8_t iv[AES_BLOCK_LEN]) {
  uint8_t i;
  for (i = 0; i < AES_BLOCK_LEN; ++i)
    state->hash[i] = iv[i];
  state->length = 0;
}

void aes_hash_update(struct aes_hash_state *state, const uint8_t *plain,
                     uint32_t length) {
  uint8_t i;

  while (length > 0) {
    /* Try to fill one plain block. */
    for (i = state->length; i < AES_KEY_LEN && length > 0; i++, length--)
      state->plain[i] = *plain++;

    if (i >= AES_KEY_LEN) {
      /* Block filled. Encrypt. */
      aes_ecb_encrypt(state->plain, state->hash, state->hash);
      state->length = 0;
    } else {
      state->length = i;
    }
  }
}

void aes_hash_finish(struct aes_hash_state *state) {
  uint8_t i = state->length;

  /* Mark end of data. */
  state->plain[i++] = 0x80;

  /* Fill the block. */
  for (; i < AES_KEY_LEN; i++)
    state->plain[i] = 0x00;

  /* Encrypt. */
  aes_ecb_encrypt(state->plain, state->hash, state->hash);
}
