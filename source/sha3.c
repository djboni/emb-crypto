/*
 SHA3 implementation.

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

#include "sha3.h"
#include "keccak.h"

void SHA3_512Init(struct sha3_512_t *state_ptr) {
  KeccakInit(&state_ptr->hash);
}

void SHA3_512Update(struct sha3_512_t *state_ptr, const void *data_ptr,
                    uint16_t num) {
  const uint8_t rate = 72;

  KeccakAbsorb(&state_ptr->hash, rate, 24, data_ptr, num);
}

void SHA3_512Finish(struct sha3_512_t *state_ptr) {
  const uint8_t state_size = 200;
  const uint8_t output = 64;
  const uint8_t rate = 72;
  uint8_t i;
  uint8_t *a_ptr = (uint8_t *)&state_ptr->hash.a[0];

  KeccakFinish(&state_ptr->hash, rate, 24, KECCAK_PAD_SHA3);

  /* Zero extra bytes. */
  for (i = output; i < state_size; ++i)
    a_ptr[i] = 0;
}

void SHA3_384Init(struct sha3_384_t *state_ptr) {
  KeccakInit(&state_ptr->hash);
}

void SHA3_384Update(struct sha3_384_t *state_ptr, const void *data_ptr,
                    uint16_t num) {
  const uint8_t rate = 104;

  KeccakAbsorb(&state_ptr->hash, rate, 24, data_ptr, num);
}

void SHA3_384Finish(struct sha3_384_t *state_ptr) {
  const uint8_t state_size = 200;
  const uint8_t output = 48;
  const uint8_t rate = 104;
  uint8_t i;
  uint8_t *a_ptr = (uint8_t *)&state_ptr->hash.a[0];

  KeccakFinish(&state_ptr->hash, rate, 24, KECCAK_PAD_SHA3);

  /* Zero extra bytes. */
  for (i = output; i < state_size; ++i)
    a_ptr[i] = 0;
}

void SHA3_256Init(struct sha3_256_t *state_ptr) {
  KeccakInit(&state_ptr->hash);
}

void SHA3_256Update(struct sha3_256_t *state_ptr, const void *data_ptr,
                    uint16_t num) {
  const uint8_t rate = 136;

  KeccakAbsorb(&state_ptr->hash, rate, 24, data_ptr, num);
}

void SHA3_256Finish(struct sha3_256_t *state_ptr) {
  const uint8_t state_size = 200;
  const uint8_t output = 32;
  const uint8_t rate = 136;
  uint8_t i;
  uint8_t *a_ptr = (uint8_t *)&state_ptr->hash.a[0];

  KeccakFinish(&state_ptr->hash, rate, 24, KECCAK_PAD_SHA3);

  /* Zero extra bytes. */
  for (i = output; i < state_size; ++i)
    a_ptr[i] = 0;
}

void SHA3_224Init(struct sha3_224_t *state_ptr) {
  KeccakInit(&state_ptr->hash);
}

void SHA3_224Update(struct sha3_224_t *state_ptr, const void *data_ptr,
                    uint16_t num) {
  const uint8_t rate = 144;

  KeccakAbsorb(&state_ptr->hash, rate, 24, data_ptr, num);
}

void SHA3_224Finish(struct sha3_224_t *state_ptr) {
  const uint8_t state_size = 200;
  const uint8_t output = 28;
  const uint8_t rate = 144;
  uint8_t i;
  uint8_t *a_ptr = (uint8_t *)&state_ptr->hash.a[0];

  KeccakFinish(&state_ptr->hash, rate, 24, KECCAK_PAD_SHA3);

  /* Zero extra bytes. */
  for (i = output; i < state_size; ++i)
    a_ptr[i] = 0;
}

void SHAKE256Init(struct shake_256_t *state_ptr) {
  KeccakInit(&state_ptr->hash);
}

void SHAKE256Domain(struct shake_256_t *state_ptr, const void *domain_ptr,
                    uint16_t domain_length) {
  SHAKE256Absorb(state_ptr, domain_ptr, domain_length);
  SHAKE256Finish(state_ptr);
}

void SHAKE256Absorb(struct shake_256_t *state_ptr, const void *data_ptr,
                    uint16_t num) {
  const uint8_t rate = 136;

  KeccakAbsorb(&state_ptr->hash, rate, 24, data_ptr, num);
}

void SHAKE256Finish(struct shake_256_t *state_ptr) {
  const uint8_t rate = 136;

  KeccakFinish(&state_ptr->hash, rate, 24, KECCAK_PAD_SHAKE);
}

void SHAKE256Squeeze(struct shake_256_t *state_ptr, void *data_ptr,
                     uint16_t num) {
  const uint8_t rate = 136;

  KeccakSqueeze(&state_ptr->hash, rate, 24, data_ptr, num);
}

void SHAKE128Init(struct shake_128_t *state_ptr) {
  KeccakInit(&state_ptr->hash);
}

void SHAKE128Domain(struct shake_128_t *state_ptr, const void *domain_ptr,
                    uint16_t domain_length) {
  SHAKE128Absorb(state_ptr, domain_ptr, domain_length);
  SHAKE128Finish(state_ptr);
}

void SHAKE128Absorb(struct shake_128_t *state_ptr, const void *data_ptr,
                    uint16_t num) {
  const uint8_t rate = 168;

  KeccakAbsorb(&state_ptr->hash, rate, 24, data_ptr, num);
}

void SHAKE128Finish(struct shake_128_t *state_ptr) {
  const uint8_t rate = 168;

  KeccakFinish(&state_ptr->hash, rate, 24, KECCAK_PAD_SHAKE);
}

void SHAKE128Squeeze(struct shake_128_t *state_ptr, void *data_ptr,
                     uint16_t num) {
  const uint8_t rate = 168;

  KeccakSqueeze(&state_ptr->hash, rate, 24, data_ptr, num);
}
