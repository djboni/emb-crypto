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

#include "keccak_types.h"
#include <stdint.h>

/* KECCAK_FASTER
 * 0 => Smaller code.
 * 1 => Faster code.
 */
#ifndef KECCAK_FASTER
#define KECCAK_FASTER 1
#endif

#define KECCAK_STATE_SIZE (25 * KECCAK_WORD) /* State size in bytes. */
#define KECCAK_NR (12 + 2 * KECCAK_L)        /* Number of rounds. */

#define KECCAK_PAD_SHA3 0x06      /* SHA3 PAD start: 0110*. */
#define KECCAK_PAD_SHAKE 0x1F     /* SHAKE PAD start. 111110*. */
#define KECCAK_PAD_MULTIRATE 0x01 /* Multirate PAD start: 10*. */
#define KECCAK_PAD_END 0x80       /* PAD end: *01. */

void KeccakInit(struct keccak_t *state_ptr);

void KeccakAbsorb(struct keccak_t *state_ptr, uint8_t rate, uint8_t rounds,
                  const void *buff_ptr, uint16_t num);
void KeccakFinish(struct keccak_t *state_ptr, uint8_t rate, uint8_t rounds,
                  uint8_t pad_byte);
void KeccakSqueeze(struct keccak_t *state_ptr, uint8_t rate, uint8_t rounds,
                   void *buff_ptr, uint16_t num);

void KeccakEncrypt(struct keccak_t *state_ptr, uint8_t rate, uint8_t rounds,
                   void *buff_ptr, uint16_t num);
void KeccakDecrypt(struct keccak_t *state_ptr, uint8_t rate, uint8_t rounds,
                   void *buff_ptr, uint16_t num);

void KeccakProcessData(struct keccak_t *state_ptr, uint8_t rate, uint8_t rounds,
                       void *buff_ptr, uint16_t num,
                       void (*function_ptr)(uint8_t *state_ptr,
                                            uint8_t *buff_ptr));
void KeccakF(struct keccak_t *state_ptr, uint8_t rounds);

#ifdef __cplusplus
}
#endif

#endif /* __KECCAK__ */
