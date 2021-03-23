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

void SHA3_512_init(struct SHA3_512_t *state) { KECCAK_init(&state->hash); }

void SHA3_512_update(struct SHA3_512_t *state, const void *data, uint16_t num) {
  const uint8_t rate = 72;

  KECCAK_absorb(&state->hash, rate, 24, data, num);
}

void SHA3_512_finish(struct SHA3_512_t *state) {
  const uint8_t state_size = 200;
  const uint8_t output = 64;
  const uint8_t rate = 72;
  uint8_t i;
  uint8_t *A = (uint8_t *)&state->hash.A[0];

  KECCAK_finish(&state->hash, rate, 24, KECCAK_PAD_SHA3);

  /* Zero extra bytes. */
  for (i = output; i < state_size; ++i)
    A[i] = 0;
}

void SHA3_384_init(struct SHA3_384_t *state) { KECCAK_init(&state->hash); }

void SHA3_384_update(struct SHA3_384_t *state, const void *data, uint16_t num) {
  const uint8_t rate = 104;

  KECCAK_absorb(&state->hash, rate, 24, data, num);
}

void SHA3_384_finish(struct SHA3_384_t *state) {
  const uint8_t state_size = 200;
  const uint8_t output = 48;
  const uint8_t rate = 104;
  uint8_t i;
  uint8_t *A = (uint8_t *)&state->hash.A[0];

  KECCAK_finish(&state->hash, rate, 24, KECCAK_PAD_SHA3);

  /* Zero extra bytes. */
  for (i = output; i < state_size; ++i)
    A[i] = 0;
}

void SHA3_256_init(struct SHA3_256_t *state) { KECCAK_init(&state->hash); }

void SHA3_256_update(struct SHA3_256_t *state, const void *data, uint16_t num) {
  const uint8_t rate = 136;

  KECCAK_absorb(&state->hash, rate, 24, data, num);
}

void SHA3_256_finish(struct SHA3_256_t *state) {
  const uint8_t state_size = 200;
  const uint8_t output = 32;
  const uint8_t rate = 136;
  uint8_t i;
  uint8_t *A = (uint8_t *)&state->hash.A[0];

  KECCAK_finish(&state->hash, rate, 24, KECCAK_PAD_SHA3);

  /* Zero extra bytes. */
  for (i = output; i < state_size; ++i)
    A[i] = 0;
}

void SHA3_224_init(struct SHA3_224_t *state) { KECCAK_init(&state->hash); }

void SHA3_224_update(struct SHA3_224_t *state, const void *data, uint16_t num) {
  const uint8_t rate = 144;

  KECCAK_absorb(&state->hash, rate, 24, data, num);
}

void SHA3_224_finish(struct SHA3_224_t *state) {
  const uint8_t state_size = 200;
  const uint8_t output = 28;
  const uint8_t rate = 144;
  uint8_t i;
  uint8_t *A = (uint8_t *)&state->hash.A[0];

  KECCAK_finish(&state->hash, rate, 24, KECCAK_PAD_SHA3);

  /* Zero extra bytes. */
  for (i = output; i < state_size; ++i)
    A[i] = 0;
}

void SHAKE_256_init(struct SHAKE_256_t *state) { KECCAK_init(&state->hash); }

void SHAKE_256_domain(struct SHAKE_256_t *state, const void *domain,
                      uint16_t domain_length) {
  SHAKE_256_absorb(state, domain, domain_length);
  SHAKE_256_finish(state);
}

void SHAKE_256_absorb(struct SHAKE_256_t *state, const void *data,
                      uint16_t num) {
  const uint8_t rate = 136;

  KECCAK_absorb(&state->hash, rate, 24, data, num);
}

void SHAKE_256_finish(struct SHAKE_256_t *state) {
  const uint8_t rate = 136;

  KECCAK_finish(&state->hash, rate, 24, KECCAK_PAD_SHAKE);
}

void SHAKE_256_squeeze(struct SHAKE_256_t *state, void *data, uint16_t num) {
  const uint8_t rate = 136;

  KECCAK_squeeze(&state->hash, rate, 24, data, num);
}

void SHAKE_128_init(struct SHAKE_128_t *state) { KECCAK_init(&state->hash); }

void SHAKE_128_domain(struct SHAKE_128_t *state, const void *domain,
                      uint16_t domain_length) {
  SHAKE_128_absorb(state, domain, domain_length);
  SHAKE_128_finish(state);
}

void SHAKE_128_absorb(struct SHAKE_128_t *state, const void *data,
                      uint16_t num) {
  const uint8_t rate = 168;

  KECCAK_absorb(&state->hash, rate, 24, data, num);
}

void SHAKE_128_finish(struct SHAKE_128_t *state) {
  const uint8_t rate = 168;

  KECCAK_finish(&state->hash, rate, 24, KECCAK_PAD_SHAKE);
}

void SHAKE_128_squeeze(struct SHAKE_128_t *state, void *data, uint16_t num) {
  const uint8_t rate = 168;

  KECCAK_squeeze(&state->hash, rate, 24, data, num);
}
