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

#ifndef _KECCAK_TYPES_H_
#define _KECCAK_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#ifndef KECCAK_WORD
#define KECCAK_WORD 8 /* 1, 2, 4, 8. */
#endif

#if (KECCAK_WORD == 1)
#define KECCAK_L 3
typedef uint8_t keccak_uint_t;
#elif (KECCAK_WORD == 2)
#define KECCAK_L 4
typedef uint16_t keccak_uint_t;
#elif (KECCAK_WORD == 4)
#define KECCAK_L 5
typedef uint32_t keccak_uint_t;
#elif (KECCAK_WORD == 8)
#define KECCAK_L 6
typedef uint64_t keccak_uint_t;
#else
#error "Invalid parameter KECCAK_WORD. Must be 1, 2, 4, or 8."
#endif

struct keccak_t {
  keccak_uint_t a[25]; /* Keccak state. */
  uint8_t num;         /* State used bytes (absorbed or squeezed). */
};

#ifdef __cplusplus
}
#endif

#endif /* _KECCAK_TYPES_H_ */
