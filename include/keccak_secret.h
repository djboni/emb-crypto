/*
 Keccak authenticated encryption.

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

#ifndef _KECCAK_SECRET_H_
#define _KECCAK_SECRET_H_

/* KECCAK_SECRET (Based on KETJE) */

#ifdef __cplusplus
extern "C" {
#endif

#include "keccak.h"

enum keccak_secret_config_t {
/* Octave
 * Size (bytes)       Capacity/Security (bytes) Rate (bytes)
 * b=[25 50 100 200], c=min(32,floor((b-1)/2)), r=b-c
 */
#if KECCAK_WORD == 1
  /* Security sizes. */
  KECCAK_SECRET_KEY_SIZE = 12,
  KECCAK_SECRET_NONCE_SIZE = 12,
  KECCAK_SECRET_TAG_SIZE = 12,

  /* Number of rounds. */
  /* NR_STEP <= NR_STRIDE <= NR_START */
  KECCAK_SECRET_NR_START = 12,
  KECCAK_SECRET_NR_STEP = 8,
  KECCAK_SECRET_NR_STRIDE = 12,

  /* Sponge rate. */
  KECCAK_SECRET_RATE = 13
#elif KECCAK_WORD == 2
  KECCAK_SECRET_KEY_SIZE = 24,
  KECCAK_SECRET_NONCE_SIZE = 16,
  KECCAK_SECRET_TAG_SIZE = 16,

  KECCAK_SECRET_NR_START = 12,
  KECCAK_SECRET_NR_STEP = 8,
  KECCAK_SECRET_NR_STRIDE = 12,

  KECCAK_SECRET_RATE = 26
#elif KECCAK_WORD == 4
  KECCAK_SECRET_KEY_SIZE = 32,
  KECCAK_SECRET_NONCE_SIZE = 16,
  KECCAK_SECRET_TAG_SIZE = 16,

  KECCAK_SECRET_NR_START = 12,
  KECCAK_SECRET_NR_STEP = 8,
  KECCAK_SECRET_NR_STRIDE = 12,

  KECCAK_SECRET_RATE = 68
#elif KECCAK_WORD == 8
  KECCAK_SECRET_KEY_SIZE = 32,
  KECCAK_SECRET_NONCE_SIZE = 16,
  KECCAK_SECRET_TAG_SIZE = 16,

  KECCAK_SECRET_NR_START = 12,
  KECCAK_SECRET_NR_STEP = 8,
  KECCAK_SECRET_NR_STRIDE = 12,

  KECCAK_SECRET_RATE = 168
#endif
};

enum keccak_secret_pad_t {
  KECCAK_SECRET_PAD_K = 0x3F,  /* 11111110* Key. */
  KECCAK_SECRET_PAD_A = 0x3E,  /* 01111110* Associated data. */
  KECCAK_SECRET_PAD_BC = 0x3D, /* 10111110* Plaintext/Ciphertext. */
  KECCAK_SECRET_PAD_D = 0x3C   /* 00111110* Authentication tag. */
};

struct keccak_secret_t {
  struct keccak_t state;
  uint8_t pad;
};

void KeccakSecretInit(struct keccak_secret_t *secret_ptr, const void *key_ptr,
                      uint8_t key_length);

void KeccakSecretAbsorbA(struct keccak_secret_t *secret_ptr,
                         const void *buff_ptr, uint8_t buff_length);

void KeccakSecretEncryptB(struct keccak_secret_t *secret_ptr, void *buff_ptr,
                          uint8_t buff_length);
void KeccakSecretDecryptC(struct keccak_secret_t *secret_ptr, void *buff_ptr,
                          uint8_t buff_length);

void KeccakSecretSqueezeD(struct keccak_secret_t *secret_ptr, void *buff_ptr,
                          uint8_t buff_length);
uint8_t KeccakSecretVerifyD(struct keccak_secret_t *secret_ptr, void *buff_ptr,
                            uint8_t buff_length);

#ifdef __cplusplus
}
#endif

#endif /* _KECCAK_SECRET_H_ */
