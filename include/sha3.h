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

#ifndef __SHA3__
#define __SHA3__

#ifdef __cplusplus
extern "C" {
#endif

#include "keccak_types.h"
#include <stdint.h>

#if (KECCAK_WORD == 8)

struct SHA3_512_t {
  struct KECCAK_t hash;
};

struct SHA3_384_t {
  struct KECCAK_t hash;
};

struct SHA3_256_t {
  struct KECCAK_t hash;
};

struct SHA3_224_t {
  struct KECCAK_t hash;
};

struct SHAKE_256_t {
  struct KECCAK_t hash;
};

struct SHAKE_128_t {
  struct KECCAK_t hash;
};

void SHA3_512_init(struct SHA3_512_t *state);
void SHA3_512_update(struct SHA3_512_t *state, const void *data, uint16_t num);
void SHA3_512_finish(struct SHA3_512_t *state);

void SHA3_384_init(struct SHA3_384_t *state);
void SHA3_384_update(struct SHA3_384_t *state, const void *data, uint16_t num);
void SHA3_384_finish(struct SHA3_384_t *state);

void SHA3_256_init(struct SHA3_256_t *state);
void SHA3_256_update(struct SHA3_256_t *state, const void *data, uint16_t num);
void SHA3_256_finish(struct SHA3_256_t *state);

void SHA3_224_init(struct SHA3_224_t *state);
void SHA3_224_update(struct SHA3_224_t *state, const void *data, uint16_t num);
void SHA3_224_finish(struct SHA3_224_t *state);

void SHAKE_256_init(struct SHAKE_256_t *state);
void SHAKE_256_domain(struct SHAKE_256_t *state, const void *domain,
                      uint16_t domain_length);
void SHAKE_256_absorb(struct SHAKE_256_t *state, const void *data,
                      uint16_t num);
void SHAKE_256_finish(struct SHAKE_256_t *state);
void SHAKE_256_squeeze(struct SHAKE_256_t *state, void *data, uint16_t num);

void SHAKE_128_init(struct SHAKE_128_t *state);
void SHAKE_128_domain(struct SHAKE_128_t *state, const void *domain,
                      uint16_t domain_length);
void SHAKE_128_absorb(struct SHAKE_128_t *state, const void *data,
                      uint16_t num);
void SHAKE_128_finish(struct SHAKE_128_t *state);
void SHAKE_128_squeeze(struct SHAKE_128_t *state, void *data, uint16_t num);

#endif

#ifdef __cplusplus
}
#endif

#endif /* __SHA3__ */
