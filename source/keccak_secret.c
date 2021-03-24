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

static void KeccakSecretFinish(struct keccak_secret_t *secret_ptr,
                               uint8_t rounds) {
  KeccakFinish(&secret_ptr->state, KECCAK_SECRET_RATE, rounds, secret_ptr->pad);
}

void KeccakSecretInit(struct keccak_secret_t *secret_ptr, const void *key_ptr,
                      uint8_t key_length) {
  KeccakInit(&secret_ptr->state);
  secret_ptr->pad = KECCAK_SECRET_PAD_A;
  KeccakAbsorb(&secret_ptr->state, KECCAK_SECRET_RATE, KECCAK_SECRET_NR_START,
               key_ptr, key_length);
  secret_ptr->pad = KECCAK_SECRET_PAD_K;
  KeccakSecretFinish(secret_ptr, KECCAK_SECRET_NR_START);
  secret_ptr->pad = KECCAK_SECRET_PAD_A;
}

void KeccakSecretAbsorbA(struct keccak_secret_t *secret_ptr,
                         const void *buff_ptr, uint8_t buff_length) {
  if (secret_ptr->pad != KECCAK_SECRET_PAD_A) {
    KeccakSecretFinish(secret_ptr, KECCAK_SECRET_NR_STEP);
    secret_ptr->pad = KECCAK_SECRET_PAD_A;
  }
  KeccakAbsorb(&secret_ptr->state, KECCAK_SECRET_RATE, KECCAK_SECRET_NR_STEP,
               buff_ptr, buff_length);
}

void KeccakSecretEncryptB(struct keccak_secret_t *secret_ptr, void *buff_ptr,
                          uint8_t buff_length) {
  if (secret_ptr->pad != KECCAK_SECRET_PAD_BC) {
    KeccakSecretFinish(secret_ptr, KECCAK_SECRET_NR_STEP);
    secret_ptr->pad = KECCAK_SECRET_PAD_BC;
  }
  KeccakEncrypt(&secret_ptr->state, KECCAK_SECRET_RATE, KECCAK_SECRET_NR_STEP,
                buff_ptr, buff_length);
}

void KeccakSecretDecryptC(struct keccak_secret_t *secret_ptr, void *buff_ptr,
                          uint8_t buff_length) {
  if (secret_ptr->pad != KECCAK_SECRET_PAD_BC) {
    KeccakSecretFinish(secret_ptr, KECCAK_SECRET_NR_STEP);
    secret_ptr->pad = KECCAK_SECRET_PAD_BC;
  }
  KeccakDecrypt(&secret_ptr->state, KECCAK_SECRET_RATE, KECCAK_SECRET_NR_STEP,
                buff_ptr, buff_length);
}

void KeccakSecretSqueezeD(struct keccak_secret_t *secret_ptr, void *buff_ptr,
                          uint8_t buff_length) {
  if (secret_ptr->pad != KECCAK_SECRET_PAD_D) {
    KeccakSecretFinish(secret_ptr, KECCAK_SECRET_NR_STRIDE);
    secret_ptr->pad = KECCAK_SECRET_PAD_D;
  }
  KeccakSqueeze(&secret_ptr->state, KECCAK_SECRET_RATE, KECCAK_SECRET_NR_STEP,
                buff_ptr, buff_length);
}

uint8_t KeccakSecretVerifyD(struct keccak_secret_t *secret_ptr, void *buff_ptr,
                            uint8_t buff_length) {
  uint8_t *u8_ptr = buff_ptr;
  uint8_t retval;

  if (secret_ptr->pad != KECCAK_SECRET_PAD_D) {
    KeccakSecretFinish(secret_ptr, KECCAK_SECRET_NR_STRIDE);
    secret_ptr->pad = KECCAK_SECRET_PAD_D;
  }
  KeccakDecrypt(&secret_ptr->state, KECCAK_SECRET_RATE, KECCAK_SECRET_NR_STEP,
                u8_ptr, buff_length);

  retval = 1;
  while (buff_length-- > 0)
    retval &= (*u8_ptr++ == 0);
  return retval;
}
