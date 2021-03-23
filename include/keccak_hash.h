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

#ifndef __KECCAK_HASH__
#define __KECCAK_HASH__

#include "keccak.h"

#ifdef __cplusplus
extern "C" {
#endif

/* HASH (Based on SHA3) */

#ifndef KECCAK_HASH_OUTPUT
#if KECCAK_WORD == 1
#define KECCAK_HASH_OUTPUT 16
#elif KECCAK_WORD == 2
#define KECCAK_HASH_OUTPUT 16
#elif KECCAK_WORD == 4
#define KECCAK_HASH_OUTPUT 16
#elif KECCAK_WORD == 8
#define KECCAK_HASH_OUTPUT 32
/* Hash output length.
 * 64 => SHA3-512
 * 48 => SHA3-384
 * 32 => SHA3-256
 * 28 => SHA3-224
 */
#endif
#endif

#define KECCAK_HASH_RATE (KECCAK_STATE_SIZE - (2 * KECCAK_HASH_OUTPUT))
#if (KECCAK_WORD == 1 && KECCAK_HASH_RATE <= 0)
/* Be less restrictive. */
#undef KECCAK_HASH_RATE
#define KECCAK_HASH_RATE (KECCAK_STATE_SIZE - KECCAK_HASH_OUTPUT)
#endif
#define KECCAK_HASH_NR (12 + 2 * KECCAK_L)

/* XOF (Based on SHAKE) */

#ifndef KECCAK_XOF_SECURITY
#if KECCAK_WORD == 1
#define KECCAK_XOF_SECURITY 8
#elif KECCAK_WORD == 2
#define KECCAK_XOF_SECURITY 16
#elif KECCAK_WORD == 4
#define KECCAK_XOF_SECURITY 16
#elif KECCAK_WORD == 8
#define KECCAK_XOF_SECURITY 32
/* XOF maximum security.
 * 32 => SHAKE-256
 * 16 => SHAKE-128
 */
#endif
#endif

#define KECCAK_XOF_RATE (KECCAK_STATE_SIZE - (2 * KECCAK_XOF_SECURITY))
#define KECCAK_XOF_NR (12 + 2 * KECCAK_L)

/* HASH (Based on SHA3) */

typedef struct KECCAK_HASH_t {
  struct KECCAK_t state;
} KECCAK_HASH_t;

void KECCAK_HASH_init(KECCAK_HASH_t *hash);
void KECCAK_HASH_update(KECCAK_HASH_t *hash, const void *buff, uint16_t num);
void KECCAK_HASH_finish(KECCAK_HASH_t *hash);

/* XOF (Based on SHAKE) */

typedef struct KECCAK_XOF_t {
  struct KECCAK_t state;
} KECCAK_XOF_t;

void KECCAK_XOF_init(KECCAK_XOF_t *xof);
void KECCAK_XOF_domain(KECCAK_XOF_t *xof, const void *domain,
                       uint16_t domain_length);
void KECCAK_XOF_absorb(KECCAK_XOF_t *xof, const void *buff, uint16_t num);
void KECCAK_XOF_finish(KECCAK_XOF_t *xof);
void KECCAK_XOF_squeeze(KECCAK_XOF_t *xof, void *buff, uint16_t num);

#ifdef __cplusplus
}
#endif

#endif /* __KECCAK_HASH__ */
