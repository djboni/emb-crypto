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

void KeccakHashInit(struct keccak_hash_t *hash_ptr) {
  KeccakInit(&hash_ptr->state);
}

void KeccakHashUpdate(struct keccak_hash_t *hash_ptr, const void *buff_ptr,
                      uint16_t num) {
  KeccakAbsorb(&hash_ptr->state, KECCAK_HASH_RATE, KECCAK_HASH_NR, buff_ptr,
               num);
}

void KeccakHashFinish(struct keccak_hash_t *hash_ptr) {
  uint8_t i, *a_ptr = (uint8_t *)&hash_ptr->state.a[0];

  KeccakFinish(&hash_ptr->state, KECCAK_HASH_RATE, KECCAK_HASH_NR,
               KECCAK_PAD_SHA3);

  /* Zero extra bytes. */
  for (i = KECCAK_HASH_OUTPUT; i < KECCAK_STATE_SIZE; ++i)
    a_ptr[i] = 0;
}

void KeccakXofInit(struct keccak_xof_t *xof_ptr) {
  KeccakInit(&xof_ptr->state);
}

void KeccakXofDomain(struct keccak_xof_t *xof_ptr, const void *domain_ptr,
                     uint16_t domain_length) {
  /*
   * Different domains should hash_ptr to different values.
   *
   * Example: Keys of different size, even when created with the same key
   * material, must not be related (prefixes one of another). With domain_ptr
   * separation you avoid this.
   *
   * struct keccak_xof_t keygen;
   *
   * uint8_t key_material[] = "Key material";
   *
   * uint8_t key_AES128[16];
   * uint8_t key_AES192[24];
   * uint8_t key_AES256[32];
   *
   * KECCAK_XOF_init(&keygen);
   * KECCAK_XOF_domain_ptr(&keygen, "AES128", 6);
   * KECCAK_XOF_absorb(&keygen, &key_material, sizeof(key_material));
   * KECCAK_XOF_finish(&keygen);
   * KECCAK_XOF_squeeze(&keygen, key_AES128, sizeof(key_AES128));
   *
   * KECCAK_XOF_init(&keygen);
   * KECCAK_XOF_domain_ptr(&keygen, "AES192", 6);
   * KECCAK_XOF_absorb(&keygen, &key_material, sizeof(key_material));
   * KECCAK_XOF_finish(&keygen);
   * KECCAK_XOF_squeeze(&keygen, key_AES192, sizeof(key_AES192));
   *
   * KECCAK_XOF_init(&keygen);
   * KECCAK_XOF_domain_ptr(&keygen, "AES256", 6);
   * KECCAK_XOF_absorb(&keygen, &key_material, sizeof(key_material));
   * KECCAK_XOF_finish(&keygen);
   * KECCAK_XOF_squeeze(&keygen, key_AES256, sizeof(key_AES256));
   *
   */
  KeccakXofAbsorb(xof_ptr, domain_ptr, domain_length);
  KeccakXofFinish(xof_ptr);
}

void KeccakXofAbsorb(struct keccak_xof_t *xof_ptr, const void *buff_ptr,
                     uint16_t num) {
  KeccakAbsorb(&xof_ptr->state, KECCAK_XOF_RATE, KECCAK_XOF_NR, buff_ptr, num);
}

void KeccakXofFinish(struct keccak_xof_t *xof_ptr) {
  KeccakFinish(&xof_ptr->state, KECCAK_XOF_RATE, KECCAK_XOF_NR,
               KECCAK_PAD_SHAKE);
}

void KeccakXofSqueeze(struct keccak_xof_t *xof_ptr, void *buff_ptr,
                      uint16_t num) {
  KeccakSqueeze(&xof_ptr->state, KECCAK_XOF_RATE, KECCAK_XOF_NR, buff_ptr, num);
}
