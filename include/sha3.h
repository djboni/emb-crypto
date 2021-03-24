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

struct sha3_512_t {
  struct keccak_t hash;
};

struct sha3_384_t {
  struct keccak_t hash;
};

struct sha3_256_t {
  struct keccak_t hash;
};

struct sha3_224_t {
  struct keccak_t hash;
};

struct shake_256_t {
  struct keccak_t hash;
};

struct shake_128_t {
  struct keccak_t hash;
};

void SHA3_512Init(struct sha3_512_t *state_ptr);
void SHA3_512Update(struct sha3_512_t *state_ptr, const void *data_ptr,
                    uint16_t num);
void SHA3_512Finish(struct sha3_512_t *state_ptr);

void SHA3_384Init(struct sha3_384_t *state_ptr);
void SHA3_384Update(struct sha3_384_t *state_ptr, const void *data_ptr,
                    uint16_t num);
void SHA3_384Finish(struct sha3_384_t *state_ptr);

void SHA3_256Init(struct sha3_256_t *state_ptr);
void SHA3_256Update(struct sha3_256_t *state_ptr, const void *data_ptr,
                    uint16_t num);
void SHA3_256Finish(struct sha3_256_t *state_ptr);

void SHA3_224Init(struct sha3_224_t *state_ptr);
void SHA3_224Update(struct sha3_224_t *state_ptr, const void *data_ptr,
                    uint16_t num);
void SHA3_224Finish(struct sha3_224_t *state_ptr);

void SHAKE256Init(struct shake_256_t *state_ptr);
void SHAKE256Domain(struct shake_256_t *state_ptr, const void *domain_ptr,
                    uint16_t domain_length);
void SHAKE256Absorb(struct shake_256_t *state_ptr, const void *data_ptr,
                    uint16_t num);
void SHAKE256Finish(struct shake_256_t *state_ptr);
void SHAKE256Squeeze(struct shake_256_t *state_ptr, void *data_ptr,
                     uint16_t num);

void SHAKE128Init(struct shake_128_t *state_ptr);
void SHAKE128Domain(struct shake_128_t *state_ptr, const void *domain_ptr,
                    uint16_t domain_length);
void SHAKE128Absorb(struct shake_128_t *state_ptr, const void *data_ptr,
                    uint16_t num);
void SHAKE128Finish(struct shake_128_t *state_ptr);
void SHAKE128Squeeze(struct shake_128_t *state_ptr, void *data_ptr,
                     uint16_t num);

#endif

#ifdef __cplusplus
}
#endif

#endif /* __SHA3__ */
