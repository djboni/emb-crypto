/*
 SHA-3 and SHAKE implementation.

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

#include "keccak_hash.h"

#if (KECCAK_HASH_OUTPUT >= KECCAK_STATE_SIZE ||                                \
     KECCAK_HASH_RATE >= KECCAK_STATE_SIZE || KECCAK_HASH_RATE <= 0)
#error "Invalid parameter KECCAK_HASH_OUTPUT."
#endif
#if (KECCAK_HASH_NR <= 0 || KECCAK_HASH_NR > KECCAK_NR)
#error "Invalid parameter KECCAK_HASH_NR."
#endif

#if (KECCAK_XOF_SECURITY >= KECCAK_STATE_SIZE ||                               \
     KECCAK_XOF_RATE >= KECCAK_STATE_SIZE || KECCAK_XOF_RATE <= 0)
#error "Invalid rate KECCAK_XOF_RATE."
#endif
#if (KECCAK_XOF_NR <= 0 || KECCAK_XOF_NR > KECCAK_NR)
#error "Invalid parameter KECCAK_XOF_NR."
#endif

void KECCAK_HASH_init(KECCAK_HASH_t *hash) { KECCAK_init(&hash->state); }

void KECCAK_HASH_update(KECCAK_HASH_t *hash, const void *buff, uint16_t num) {
  KECCAK_absorb(&hash->state, KECCAK_HASH_RATE, KECCAK_HASH_NR, buff, num);
}

void KECCAK_HASH_finish(KECCAK_HASH_t *hash) {
  uint8_t i, *A = (uint8_t *)&hash->state.A[0];

  KECCAK_finish(&hash->state, KECCAK_HASH_RATE, KECCAK_HASH_NR,
                KECCAK_PAD_SHA3);

  /* Zero extra bytes. */
  for (i = KECCAK_HASH_OUTPUT; i < KECCAK_STATE_SIZE; ++i)
    A[i] = 0;
}

void KECCAK_XOF_init(KECCAK_XOF_t *xof) { KECCAK_init(&xof->state); }

void KECCAK_XOF_domain(KECCAK_XOF_t *xof, const void *domain,
                       uint16_t domain_length) {
  /*
   * Different domains should hash to different values.
   *
   * Example: Keys of different size, even when created with the same key
   * material, must not be related (prefixes one of another). With domain
   * separation you avoid this.
   *
   * KECCAK_XOF_t keygen;
   *
   * uint8_t key_material[] = "Key material";
   *
   * uint8_t key_AES128[16];
   * uint8_t key_AES192[24];
   * uint8_t key_AES256[32];
   *
   * KECCAK_XOF_init(&keygen);
   * KECCAK_XOF_domain(&keygen, "AES128", 6);
   * KECCAK_XOF_absorb(&keygen, &key_material, sizeof(key_material));
   * KECCAK_XOF_finish(&keygen);
   * KECCAK_XOF_squeeze(&keygen, key_AES128, sizeof(key_AES128));
   *
   * KECCAK_XOF_init(&keygen);
   * KECCAK_XOF_domain(&keygen, "AES192", 6);
   * KECCAK_XOF_absorb(&keygen, &key_material, sizeof(key_material));
   * KECCAK_XOF_finish(&keygen);
   * KECCAK_XOF_squeeze(&keygen, key_AES192, sizeof(key_AES192));
   *
   * KECCAK_XOF_init(&keygen);
   * KECCAK_XOF_domain(&keygen, "AES256", 6);
   * KECCAK_XOF_absorb(&keygen, &key_material, sizeof(key_material));
   * KECCAK_XOF_finish(&keygen);
   * KECCAK_XOF_squeeze(&keygen, key_AES256, sizeof(key_AES256));
   *
   */
  KECCAK_XOF_absorb(xof, domain, domain_length);
  KECCAK_XOF_finish(xof);
}

void KECCAK_XOF_absorb(KECCAK_XOF_t *xof, const void *buff, uint16_t num) {
  KECCAK_absorb(&xof->state, KECCAK_XOF_RATE, KECCAK_XOF_NR, buff, num);
}

void KECCAK_XOF_finish(KECCAK_XOF_t *xof) {
  KECCAK_finish(&xof->state, KECCAK_XOF_RATE, KECCAK_XOF_NR, KECCAK_PAD_SHAKE);
}

void KECCAK_XOF_squeeze(KECCAK_XOF_t *xof, void *buff, uint16_t num) {
  KECCAK_squeeze(&xof->state, KECCAK_XOF_RATE, KECCAK_XOF_NR, buff, num);
}
