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

typedef void (*function_process_data)(uint8_t *state, uint8_t *buff);

void KECCAK_init(struct KECCAK_t *state) {
  uint8_t *A = (uint8_t *)&state->A[0], i;
  for (i = 0; i < sizeof(*state); i++) {
    A[i] = 0;
  }
}

static void function_absorb(uint8_t *state, const uint8_t *buff) {
  *state ^= *buff;
}

void KECCAK_absorb(struct KECCAK_t *state, uint8_t rate, uint8_t rounds,
                   const void *buff, uint16_t num) {
  KECCAK_process_data(state, rate, rounds, (uint8_t *)buff, num,
                      (function_process_data)function_absorb);
}

void KECCAK_finish(struct KECCAK_t *state, uint8_t rate, uint8_t rounds,
                   uint8_t pad_byte) {
  uint8_t *A = (uint8_t *)&state->A[0];

  /* Pad block. */
  A[state->num] ^= pad_byte;
  A[rate - 1] ^= KECCAK_PAD_END;

  KECCAK_f(state, rounds);
}

static void function_squeeze(const uint8_t *state, uint8_t *buff) {
  *buff = *state;
}

void KECCAK_squeeze(struct KECCAK_t *state, uint8_t rate, uint8_t rounds,
                    void *buff, uint16_t num) {
  KECCAK_process_data(state, rate, rounds, buff, num,
                      (function_process_data)function_squeeze);
}

static void function_encrypt(uint8_t *state, uint8_t *buff) {
  uint8_t encrypted = *state ^ *buff;
  *state = encrypted;
  *buff = encrypted;
}

void KECCAK_encrypt(struct KECCAK_t *state, uint8_t rate, uint8_t rounds,
                    void *buff, uint16_t num) {
  KECCAK_process_data(state, rate, rounds, buff, num, function_encrypt);
}

static void function_decrypt(uint8_t *state, uint8_t *buff) {
  uint8_t decrypted = *state ^ *buff;
  *state = *buff;
  *buff = decrypted;
}

void KECCAK_decrypt(struct KECCAK_t *state, uint8_t rate, uint8_t rounds,
                    void *buff, uint16_t num) {
  KECCAK_process_data(state, rate, rounds, buff, num, function_decrypt);
}

void KECCAK_process_data(struct KECCAK_t *state, uint8_t rate, uint8_t rounds,
                         void *buff, uint16_t num,
                         void (*function)(uint8_t *state, uint8_t *buff)) {
  uint8_t statenum = state->num;
  uint8_t *in = buff;
  uint8_t *out = ((uint8_t *)&state->A[0]) + statenum;

  while (num-- > 0) {
    function(out++, in++);

    if (++statenum >= rate) {
      /* Block complete. */
      KECCAK_f(state, rounds);
      statenum = 0;
      out = (uint8_t *)&state->A[0];
    }
  }
  state->num = statenum;
}

static void KECCAK_f_round(struct KECCAK_t *state, uint8_t round);

void KECCAK_f(struct KECCAK_t *state, uint8_t rounds) {
  uint8_t i;
  for (i = KECCAK_NR - rounds; i < KECCAK_NR; ++i)
    KECCAK_f_round(state, i);
  state->num = 0;
}

#ifdef AVR
#include <avr/pgmspace.h>
#if (KECCAK_WORD == 1)
#define pgm_read_KECCAK_WORD(x) pgm_read_byte(x)
#elif (KECCAK_WORD == 2)
#define pgm_read_KECCAK_WORD(x) pgm_read_word(x)
#elif (KECCAK_WORD == 4)
#define pgm_read_KECCAK_WORD(x) pgm_read_dword(x)
#elif (KECCAK_WORD == 8)
#define pgm_read_KECCAK_WORD(x) pgm_read_qword(x)
#endif
#else
#undef PROGMEM
#define PROGMEM
#undef pgm_read_byte
#define pgm_read_byte(x) *(x)
#if (KECCAK_WORD == 1)
#define pgm_read_KECCAK_WORD(x) *(x)
#elif (KECCAK_WORD == 2)
#define pgm_read_KECCAK_WORD(x) *(x)
#elif (KECCAK_WORD == 4)
#define pgm_read_KECCAK_WORD(x) *(x)
#elif (KECCAK_WORD == 8)
#define pgm_read_KECCAK_WORD(x) *(x)
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
#define Krcm 0xFF
#define Krtm 0x07
#elif (KECCAK_WORD == 2)
#define Krcm 0xFFFF
#define Krtm 0x0F
#elif (KECCAK_WORD == 4)
#define Krcm 0xFFFFFFFF
#define Krtm 0x1F
#elif (KECCAK_WORD == 8)
#define Krcm 0xFFFFFFFFFFFFFFFF
#define Krtm 0x3F
#endif

PROGMEM
static const KECCAK_uint Krc[KECCAK_NR] = {0x0000000000000001 & Krcm,
                                           0x0000000000008082 & Krcm,
                                           0x800000000000808A & Krcm,
                                           0x8000000080008000 & Krcm,
                                           0x000000000000808B & Krcm,
                                           0x0000000080000001 & Krcm,
                                           0x8000000080008081 & Krcm,
                                           0x8000000000008009 & Krcm,
                                           0x000000000000008A & Krcm,
                                           0x0000000000000088 & Krcm,
                                           0x0000000080008009 & Krcm,
                                           0x000000008000000A & Krcm,
                                           0x000000008000808B & Krcm,
                                           0x800000000000008B & Krcm,
                                           0x8000000000008089 & Krcm,
                                           0x8000000000008003 & Krcm,
                                           0x8000000000008002 & Krcm,
                                           0x8000000000000080 & Krcm,
#if KECCAK_WORD >= 2
                                           0x000000000000800A & Krcm,
                                           0x800000008000000A & Krcm,
#endif
#if KECCAK_WORD >= 4
                                           0x8000000080008081 & Krcm,
                                           0x8000000000008080 & Krcm,
#endif
#if KECCAK_WORD >= 8
                                           0x0000000080000001 & Krcm,
                                           0x8000000080008008 & Krcm
#endif
};

PROGMEM
static const uint8_t Krho[25] = {
    0 & Krtm,  1 & Krtm,  62 & Krtm, 28 & Krtm, 27 & Krtm, 36 & Krtm, 44 & Krtm,
    6 & Krtm,  55 & Krtm, 20 & Krtm, 3 & Krtm,  10 & Krtm, 43 & Krtm, 25 & Krtm,
    39 & Krtm, 41 & Krtm, 45 & Krtm, 15 & Krtm, 21 & Krtm, 8 & Krtm,  18 & Krtm,
    2 & Krtm,  61 & Krtm, 56 & Krtm, 14 & Krtm};

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

static KECCAK_uint rot(KECCAK_uint x, uint8_t n) {
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

static void KECCAK_f_round(struct KECCAK_t *state, uint8_t round) {
  uint8_t i, im1, ip1, jt5;
  KECCAK_uint B[25], C[5], D;

  /* Theta Rho Pi */
  for (i = 0; i < 5; ++i) {
    C[i] = (state->A[i] ^ state->A[5 + i] ^ state->A[10 + i] ^
            state->A[15 + i] ^ state->A[20 + i]);
  }
  for (i = 0, im1 = 4, ip1 = 1; i < 5; ++i) {
    D = C[im1] ^ rot(C[ip1], 1);

    for (jt5 = 0; jt5 < 25; jt5 += 5) {
      uint8_t k = jt5 + i;
      B[pgm_read_byte(&Kpi[k])] = rot(state->A[k] ^ D, pgm_read_byte(&Krho[k]));
    }

    if (++im1 >= 5)
      im1 = 0;
    if (++ip1 >= 5)
      ip1 = 0;
  }

  /* Chi */
  for (i = 0; i < 25; ++i) {
    state->A[i] =
        B[i] ^ ((~B[pgm_read_byte(&Kiip1[i])]) & B[pgm_read_byte(&Kiip2[i])]);
  }

  /* Iota */
  state->A[0] ^= pgm_read_KECCAK_WORD(&Krc[round]);
}
