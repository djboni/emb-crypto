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

#include "keccak.h"

typedef void (*function_process_data)(uint8_t *state_ptr, uint8_t *buff_ptr);

void KeccakInit(struct keccak_t *state_ptr) {
  uint8_t *a_ptr = (uint8_t *)&state_ptr->a[0], i;
  for (i = 0; i < sizeof(*state_ptr); i++) {
    a_ptr[i] = 0;
  }
}

static void FunctionAbsorb(uint8_t *state_ptr, const uint8_t *buff_ptr) {
  *state_ptr ^= *buff_ptr;
}

void KeccakAbsorb(struct keccak_t *state_ptr, uint8_t rate, uint8_t rounds,
                  const void *buff_ptr, uint16_t num) {
  KeccakProcessData(state_ptr, rate, rounds, (uint8_t *)buff_ptr, num,
                    (function_process_data)FunctionAbsorb);
}

void KeccakFinish(struct keccak_t *state_ptr, uint8_t rate, uint8_t rounds,
                  uint8_t pad_byte) {
  uint8_t *a_ptr = (uint8_t *)&state_ptr->a[0];

  /* Pad block. */
  a_ptr[state_ptr->num] ^= pad_byte;
  a_ptr[rate - 1] ^= KECCAK_PAD_END;

  KeccakF(state_ptr, rounds);
}

static void FunctionSqueeze(const uint8_t *state_ptr, uint8_t *buff_ptr) {
  *buff_ptr = *state_ptr;
}

void KeccakSqueeze(struct keccak_t *state_ptr, uint8_t rate, uint8_t rounds,
                   void *buff_ptr, uint16_t num) {
  KeccakProcessData(state_ptr, rate, rounds, buff_ptr, num,
                    (function_process_data)FunctionSqueeze);
}

static void FunctionEncrypt(uint8_t *state_ptr, uint8_t *buff_ptr) {
  uint8_t encrypted = *state_ptr ^ *buff_ptr;
  *state_ptr = encrypted;
  *buff_ptr = encrypted;
}

void KeccakEncrypt(struct keccak_t *state_ptr, uint8_t rate, uint8_t rounds,
                   void *buff_ptr, uint16_t num) {
  KeccakProcessData(state_ptr, rate, rounds, buff_ptr, num, FunctionEncrypt);
}

static void FunctionDecrypt(uint8_t *state_ptr, uint8_t *buff_ptr) {
  uint8_t decrypted = *state_ptr ^ *buff_ptr;
  *state_ptr = *buff_ptr;
  *buff_ptr = decrypted;
}

void KeccakDecrypt(struct keccak_t *state_ptr, uint8_t rate, uint8_t rounds,
                   void *buff_ptr, uint16_t num) {
  KeccakProcessData(state_ptr, rate, rounds, buff_ptr, num, FunctionDecrypt);
}

void KeccakProcessData(struct keccak_t *state_ptr, uint8_t rate, uint8_t rounds,
                       void *buff_ptr, uint16_t num,
                       void (*function_ptr)(uint8_t *state_ptr,
                                            uint8_t *buff_ptr)) {
  uint8_t statenum = state_ptr->num;
  uint8_t *in_ptr = buff_ptr;
  uint8_t *out_ptr = ((uint8_t *)&state_ptr->a[0]) + statenum;

  while (num-- > 0) {
    function_ptr(out_ptr++, in_ptr++);

    if (++statenum >= rate) {
      /* Block complete. */
      KeccakF(state_ptr, rounds);
      statenum = 0;
      out_ptr = (uint8_t *)&state_ptr->a[0];
    }
  }
  state_ptr->num = statenum;
}

static void KeccakFRound(struct keccak_t *state_ptr, uint8_t round);

void KeccakF(struct keccak_t *state_ptr, uint8_t rounds) {
  uint8_t i;
  for (i = KECCAK_NR - rounds; i < KECCAK_NR; ++i)
    KeccakFRound(state_ptr, i);
  state_ptr->num = 0;
}

#ifdef AVR
#include <avr/pgmspace.h>
#define PGM_READ_BYTE(x) pgm_read_byte(x)
#if (KECCAK_WORD == 1)
#define PGM_READ_KECCAK_WORD(x) pgm_read_byte(x)
#elif (KECCAK_WORD == 2)
#define PGM_READ_KECCAK_WORD(x) pgm_read_word(x)
#elif (KECCAK_WORD == 4)
#define PGM_READ_KECCAK_WORD(x) pgm_read_dword(x)
#elif (KECCAK_WORD == 8)
#define PGM_READ_KECCAK_WORD(x) pgm_read_qword(x)
#endif
#else
#undef PROGMEM
#define PROGMEM
#define PGM_READ_BYTE(x) *(x)
#if (KECCAK_WORD == 1)
#define PGM_READ_KECCAK_WORD(x) *(x)
#elif (KECCAK_WORD == 2)
#define PGM_READ_KECCAK_WORD(x) *(x)
#elif (KECCAK_WORD == 4)
#define PGM_READ_KECCAK_WORD(x) *(x)
#elif (KECCAK_WORD == 8)
#define PGM_READ_KECCAK_WORD(x) *(x)
#endif
#endif

#if defined(AVR) && (KECCAK_WORD == 8)
static uint64_t pgm_read_qword(const void *address) {
  uint32_t low = pgm_read_dword(address);
  uint32_t high = pgm_read_dword(address + 4);
  return ((uint64_t)high << 32) | low;
}
#endif

#if (KECCAK_WORD == 1)
#define KRCM 0xFF
#define KRTM 0x07
#elif (KECCAK_WORD == 2)
#define KRCM 0xFFFF
#define KRTM 0x0F
#elif (KECCAK_WORD == 4)
#define KRCM 0xFFFFFFFF
#define KRTM 0x1F
#elif (KECCAK_WORD == 8)
#define KRCM 0xFFFFFFFFFFFFFFFF
#define KRTM 0x3F
#endif

PROGMEM
static const keccak_uint_t Krc[KECCAK_NR] = {0x0000000000000001 & KRCM,
                                             0x0000000000008082 & KRCM,
                                             0x800000000000808A & KRCM,
                                             0x8000000080008000 & KRCM,
                                             0x000000000000808B & KRCM,
                                             0x0000000080000001 & KRCM,
                                             0x8000000080008081 & KRCM,
                                             0x8000000000008009 & KRCM,
                                             0x000000000000008A & KRCM,
                                             0x0000000000000088 & KRCM,
                                             0x0000000080008009 & KRCM,
                                             0x000000008000000A & KRCM,
                                             0x000000008000808B & KRCM,
                                             0x800000000000008B & KRCM,
                                             0x8000000000008089 & KRCM,
                                             0x8000000000008003 & KRCM,
                                             0x8000000000008002 & KRCM,
                                             0x8000000000000080 & KRCM,
#if KECCAK_WORD >= 2
                                             0x000000000000800A & KRCM,
                                             0x800000008000000A & KRCM,
#endif
#if KECCAK_WORD >= 4
                                             0x8000000080008081 & KRCM,
                                             0x8000000000008080 & KRCM,
#endif
#if KECCAK_WORD >= 8
                                             0x0000000080000001 & KRCM,
                                             0x8000000080008008 & KRCM
#endif
};

PROGMEM
static const uint8_t Krho[25] = {
    0 & KRTM,  1 & KRTM,  62 & KRTM, 28 & KRTM, 27 & KRTM, 36 & KRTM, 44 & KRTM,
    6 & KRTM,  55 & KRTM, 20 & KRTM, 3 & KRTM,  10 & KRTM, 43 & KRTM, 25 & KRTM,
    39 & KRTM, 41 & KRTM, 45 & KRTM, 15 & KRTM, 21 & KRTM, 8 & KRTM,  18 & KRTM,
    2 & KRTM,  61 & KRTM, 56 & KRTM, 14 & KRTM};

PROGMEM
static const uint8_t Kpi[25] = {0,  10, 20, 5, 15, 16, 1,  11, 21, 6, 7,  17, 2,
                                12, 22, 23, 8, 18, 3,  13, 14, 24, 9, 19, 4};

PROGMEM
static const uint8_t Kiip1[25] = {1,  2,  3,  4,  0,  6,  7,  8,  9,
                                  5,  11, 12, 13, 14, 10, 16, 17, 18,
                                  19, 15, 21, 22, 23, 24, 20};

PROGMEM
static const uint8_t Kiip2[25] = {2,  3,  4,  0,  1,  7,  8,  9,  5,
                                  6,  12, 13, 14, 10, 11, 17, 18, 19,
                                  15, 16, 22, 23, 24, 20, 21};

static keccak_uint_t Rot(keccak_uint_t x, uint8_t n) {
#if (KECCAK_WORD == 1 && KECCAK_FASTER != 0)
  /* On AVR this is faster for KECCAK_WORD == 1. */
  if (n == 0)
    return x;
  else if (n == 1)
    return (x << 1) | (x >> ((8 * KECCAK_WORD) - 1));
  else if (n == 2)
    return (x << 2) | (x >> ((8 * KECCAK_WORD) - 2));
  else if (n == 3)
    return (x << 3) | (x >> ((8 * KECCAK_WORD) - 3));
  else if (n == 4)
    return (x << 4) | (x >> ((8 * KECCAK_WORD) - 4));
  else if (n == 5)
    return (x << 5) | (x >> ((8 * KECCAK_WORD) - 5));
  else if (n == 6)
    return (x << 6) | (x >> ((8 * KECCAK_WORD) - 6));
  else if (n == 7)
    return (x << 7) | (x >> ((8 * KECCAK_WORD) - 7));
#if KECCAK_WORD >= 2
  else if (n < 16)
    return rot((x << 8) | (x >> ((8 * KECCAK_WORD) - 8)), n - 8);
#endif
#if KECCAK_WORD >= 4
  else if (n < 24)
    return rot((x << 16) | (x >> ((8 * KECCAK_WORD) - 16)), n - 16);
  else if (n < 32)
    return rot((x << 24) | (x >> ((8 * KECCAK_WORD) - 24)), n - 24);
#endif
#if KECCAK_WORD >= 8
  else if (n < 40)
    return rot((x << 32) | (x >> ((8 * KECCAK_WORD) - 32)), n - 32);
  else if (n < 48)
    return rot((x << 40) | (x >> ((8 * KECCAK_WORD) - 40)), n - 40);
  else if (n < 56)
    return rot((x << 48) | (x >> ((8 * KECCAK_WORD) - 48)), n - 48);
  else if (n < 64)
    return rot((x << 56) | (x >> ((8 * KECCAK_WORD) - 56)), n - 56);
#endif
  else
    return 0;
#else
  return (x << n) | (x >> ((8 * KECCAK_WORD) - n));
#endif
}

static void KeccakFRound(struct keccak_t *state_ptr, uint8_t round) {
  uint8_t i, im1, ip1, jt5;
  keccak_uint_t b[25], c[5], d;

  /* Theta Rho Pi */
  for (i = 0; i < 5; ++i) {
    c[i] = (state_ptr->a[i] ^ state_ptr->a[5 + i] ^ state_ptr->a[10 + i] ^
            state_ptr->a[15 + i] ^ state_ptr->a[20 + i]);
  }
  for (i = 0, im1 = 4, ip1 = 1; i < 5; ++i) {
    d = c[im1] ^ Rot(c[ip1], 1);

    for (jt5 = 0; jt5 < 25; jt5 += 5) {
      uint8_t k = jt5 + i;
      b[PGM_READ_BYTE(&Kpi[k])] =
          Rot(state_ptr->a[k] ^ d, PGM_READ_BYTE(&Krho[k]));
    }

    if (++im1 >= 5)
      im1 = 0;
    if (++ip1 >= 5)
      ip1 = 0;
  }

  /* Chi */
  for (i = 0; i < 25; ++i) {
    state_ptr->a[i] =
        b[i] ^ ((~b[PGM_READ_BYTE(&Kiip1[i])]) & b[PGM_READ_BYTE(&Kiip2[i])]);
  }

  /* Iota */
  state_ptr->a[0] ^= PGM_READ_KECCAK_WORD(&Krc[round]);
}
