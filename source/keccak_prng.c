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

#include "keccak_prng.h"

#if (KECCAK_PRNG_RATE >= KECCAK_STATE_SIZE || KECCAK_PRNG_RATE <= 0)
#error "Invalid rate KECCAK_PRNG_RATE."
#endif
#if (KECCAK_PRNG_NR_START <= 0 || KECCAK_PRNG_NR_START > KECCAK_NR)
#error "Invalid parameter KECCAK_PRNG_NR_START."
#endif
#if (KECCAK_PRNG_NR_STEP <= 0 || KECCAK_PRNG_NR_STEP > KECCAK_NR)
#error "Invalid parameter KECCAK_PRNG_NR_STEP."
#endif

/******************************************************************************/

/*
 * If the PRNG is DETERMINISTIC (KECCAK_PRNG_DEBUG == 1) the state
 * will be zeroed at the start of seed(), and data in buff_ptr at the start of
 * random() is NOT inserted into the entropy pool.
 *
 * A DETERMINISTIC PRNG is useful for testing software (with test vectors).
 * In general, if you actually need a DETERMINISTIC PRNG use KECCAK_XOF instead.
 *
 * Things you can send into the entropy pool via buff_ptr when calling seed() or
 * random():
 *
 * - Anything that is unpredictible to an attacker.
 *
 * - ADC readings.
 *   In general ADCs have noise in the LSBs.
 *
 * - Timer count on unpredictible events or interrupts.
 *   Serial receive complete, Pin interrupt...
 *
 * - RAM section is not zeroed on initialization (section .noinit).
 */

#if defined(KECCAK_PRNG_DEBUG) && KECCAK_PRNG_DEBUG == 1
struct keccak_t Keccak_Prng_Entropy __attribute__((section(".noinit")));
#else
static struct keccak_t keccak_prng_entropy __attribute__((section(".noinit")));
#endif

void KeccakPrngSeed(const void *buff_ptr, uint8_t num) {
#if defined(KECCAK_PRNG_DEBUG) && KECCAK_PRNG_DEBUG == 1
  KeccakInit(&Keccak_Prng_Entropy);
  KeccakAbsorb(&Keccak_Prng_Entropy, KECCAK_STATE_SIZE, KECCAK_PRNG_NR_STEP,
               buff_ptr, num);
  KeccakFinish(&Keccak_Prng_Entropy, KECCAK_STATE_SIZE, KECCAK_PRNG_NR_START,
               KECCAK_PAD_MULTIRATE);
#else
  KeccakAbsorb(&keccak_prng_entropy, KECCAK_STATE_SIZE, KECCAK_PRNG_NR_STEP,
               buff_ptr, num);
  KeccakFinish(&keccak_prng_entropy, KECCAK_STATE_SIZE, KECCAK_PRNG_NR_START,
               KECCAK_PAD_MULTIRATE);
#endif
}

void KeccakPrngRandom(void *buff_ptr, uint8_t num) {
#if defined(KECCAK_PRNG_DEBUG) && KECCAK_PRNG_DEBUG == 1
  KeccakSqueeze(&Keccak_Prng_Entropy, KECCAK_PRNG_RATE, KECCAK_PRNG_NR_STEP,
                buff_ptr, num);
#else
  KeccakEncrypt(&keccak_prng_entropy, KECCAK_PRNG_RATE, KECCAK_PRNG_NR_STEP,
                buff_ptr, num);
#endif
}
