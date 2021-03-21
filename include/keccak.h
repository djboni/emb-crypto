/*
 Keccak implementation.

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

#ifndef __KECCAK__
#define __KECCAK__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#ifndef KECCAK_WORD
#define KECCAK_WORD 8 /* 1, 2, 4, 8. */
#endif

/* KECCAK_FASTER
 * 0 => Smaller code.
 * 1 => Faster code.
 */
#ifndef KECCAK_FASTER
#define KECCAK_FASTER 1
#endif

#if (KECCAK_WORD == 1)
#define KECCAK_L 3
#define KECCAK_uint uint8_t
#elif (KECCAK_WORD == 2)
#define KECCAK_L 4
#define KECCAK_uint uint16_t
#elif (KECCAK_WORD == 4)
#define KECCAK_L 5
#define KECCAK_uint uint32_t
#elif (KECCAK_WORD == 8)
#define KECCAK_L 6
#define KECCAK_uint uint64_t
#else
#error "Invalid parameter KECCAK_WORD. Must be 1, 2, 4, or 8."
#endif

#define KECCAK_STATE_SIZE (25 * KECCAK_WORD) /* State size in bytes. */
#define KECCAK_NR (12 + 2 * KECCAK_L)        /* Number of rounds. */

#define KECCAK_PAD_SHA3 0x06      /* SHA3 PAD start: 0110*. */
#define KECCAK_PAD_SHAKE 0x1F     /* SHAKE PAD start. 111110*. */
#define KECCAK_PAD_MULTIRATE 0x01 /* Multirate PAD start: 10*. */
#define KECCAK_PAD_END 0x80       /* PAD end: *01. */

typedef struct KECCAK_t {
  KECCAK_uint A[25]; /* Keccak state. */
  uint8_t num;       /* State used bytes (absorbed or squeezed). */
} KECCAK_t;

void KECCAK_init(KECCAK_t *state);

void KECCAK_absorb(KECCAK_t *state, uint8_t rate, uint8_t rounds,
                   const void *buff, uint16_t num);
void KECCAK_finish(KECCAK_t *state, uint8_t rate, uint8_t rounds,
                   uint8_t pad_byte);
void KECCAK_squeeze(KECCAK_t *state, uint8_t rate, uint8_t rounds, void *buff,
                    uint16_t num);

void KECCAK_encrypt(KECCAK_t *state, uint8_t rate, uint8_t rounds, void *buff,
                    uint16_t num);
void KECCAK_decrypt(KECCAK_t *state, uint8_t rate, uint8_t rounds, void *buff,
                    uint16_t num);

void KECCAK_process_data(KECCAK_t *state, uint8_t rate, uint8_t rounds,
                         void *buff, uint16_t num,
                         void (*function)(uint8_t *state, uint8_t *buff));
void KECCAK_f(KECCAK_t *state, uint8_t rounds);

#ifdef __cplusplus
}
#endif

#endif /* __KECCAK__ */
