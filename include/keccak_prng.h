/*
 Keccak PRNG (pseudo random number generator).

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

#ifndef _KECCAK_PRNG_H_
#define _KECCAK_PRNG_H_

#include "keccak.h"

#ifdef __cplusplus
extern "C" {
#endif

/* KECCAK_PRNG (Based on KETJE) */

#ifndef KECCAK_PRNG_RATE
#if KECCAK_WORD == 1
#define KECCAK_PRNG_RATE 2
#elif KECCAK_WORD == 2
#define KECCAK_PRNG_RATE 4
#elif KECCAK_WORD == 4
#define KECCAK_PRNG_RATE 16
#elif KECCAK_WORD == 8
#define KECCAK_PRNG_RATE 32
#endif
#endif

#define KECCAK_PRNG_NR_START 12
#define KECCAK_PRNG_NR_STEP 1

void KeccakPrngSeed(const void *buff_ptr, uint8_t num);
void KeccakPrngRandom(void *buff_ptr, uint8_t num);

#ifdef KECCAK_PRNG_DEBUG
extern struct keccak_t Keccak_Prng_Entropy __attribute__((section(".noinit")));
#endif

#ifdef __cplusplus
}
#endif

#endif /* _KECCAK_PRNG_H_ */
