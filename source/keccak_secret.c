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

#include "keccak_secret.h"

static void KECCAK_SECRET_finish(KECCAK_SECRET_t *secret, uint8_t rounds) {
  KECCAK_finish(&secret->state, KECCAK_SECRET_RATE, rounds, secret->pad);
}

void KECCAK_SECRET_init(KECCAK_SECRET_t *secret, const void *key,
                        uint8_t key_length) {
  KECCAK_init(&secret->state);
  secret->pad = KECCAK_SECRET_PAD_A;
  KECCAK_absorb(&secret->state, KECCAK_SECRET_RATE, KECCAK_SECRET_NR_START, key,
                key_length);
  secret->pad = KECCAK_SECRET_PAD_K;
  KECCAK_SECRET_finish(secret, KECCAK_SECRET_NR_START);
  secret->pad = KECCAK_SECRET_PAD_A;
}

void KECCAK_SECRET_absorb_A(KECCAK_SECRET_t *secret, const void *buff,
                            uint8_t buff_length) {
  if (secret->pad != KECCAK_SECRET_PAD_A) {
    KECCAK_SECRET_finish(secret, KECCAK_SECRET_NR_STEP);
    secret->pad = KECCAK_SECRET_PAD_A;
  }
  KECCAK_absorb(&secret->state, KECCAK_SECRET_RATE, KECCAK_SECRET_NR_STEP, buff,
                buff_length);
}

void KECCAK_SECRET_encrypt_B(KECCAK_SECRET_t *secret, void *buff,
                             uint8_t buff_length) {
  if (secret->pad != KECCAK_SECRET_PAD_BC) {
    KECCAK_SECRET_finish(secret, KECCAK_SECRET_NR_STEP);
    secret->pad = KECCAK_SECRET_PAD_BC;
  }
  KECCAK_encrypt(&secret->state, KECCAK_SECRET_RATE, KECCAK_SECRET_NR_STEP,
                 buff, buff_length);
}

void KECCAK_SECRET_decrypt_C(KECCAK_SECRET_t *secret, void *buff,
                             uint8_t buff_length) {
  if (secret->pad != KECCAK_SECRET_PAD_BC) {
    KECCAK_SECRET_finish(secret, KECCAK_SECRET_NR_STEP);
    secret->pad = KECCAK_SECRET_PAD_BC;
  }
  KECCAK_decrypt(&secret->state, KECCAK_SECRET_RATE, KECCAK_SECRET_NR_STEP,
                 buff, buff_length);
}

void KECCAK_SECRET_squeeze_D(KECCAK_SECRET_t *secret, void *buff,
                             uint8_t buff_length) {
  if (secret->pad != KECCAK_SECRET_PAD_D) {
    KECCAK_SECRET_finish(secret, KECCAK_SECRET_NR_STRIDE);
    secret->pad = KECCAK_SECRET_PAD_D;
  }
  KECCAK_squeeze(&secret->state, KECCAK_SECRET_RATE, KECCAK_SECRET_NR_STEP,
                 buff, buff_length);
}

uint8_t KECCAK_SECRET_verify_D(KECCAK_SECRET_t *secret, void *buff,
                               uint8_t buff_length) {
  uint8_t *buff_ = buff;
  uint8_t retval;

  if (secret->pad != KECCAK_SECRET_PAD_D) {
    KECCAK_SECRET_finish(secret, KECCAK_SECRET_NR_STRIDE);
    secret->pad = KECCAK_SECRET_PAD_D;
  }
  KECCAK_decrypt(&secret->state, KECCAK_SECRET_RATE, KECCAK_SECRET_NR_STEP,
                 buff_, buff_length);

  retval = 1;
  while (buff_length-- > 0)
    retval &= (*buff_++ == 0);
  return retval;
}
