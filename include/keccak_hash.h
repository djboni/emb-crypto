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

#ifndef _KECCAK_HASH_H_
#define _KECCAK_HASH_H_

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

struct keccak_hash_t {
  struct keccak_t state;
};

void KeccakHashInit(struct keccak_hash_t *hash_ptr);
void KeccakHashUpdate(struct keccak_hash_t *hash_ptr, const void *buff_ptr,
                      uint16_t num);
void KeccakHashFinish(struct keccak_hash_t *hash_ptr);

/* XOF (Based on SHAKE) */

struct keccak_xof_t {
  struct keccak_t state;
};

void KeccakXofInit(struct keccak_xof_t *xof_ptr);
void KeccakXofDomain(struct keccak_xof_t *xof_ptr, const void *domain_ptr,
                     uint16_t domain_length);
void KeccakXofAbsorb(struct keccak_xof_t *xof_ptr, const void *buff_ptr,
                     uint16_t num);
void KeccakXofFinish(struct keccak_xof_t *xof_ptr);
void KeccakXofSqueeze(struct keccak_xof_t *xof_ptr, void *buff_ptr,
                      uint16_t num);

#ifdef __cplusplus
}
#endif

#endif /* _KECCAK_HASH_H_ */
