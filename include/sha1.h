/*
 SHA1 implementation.

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

#ifndef __SHA1__
#define __SHA1__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

struct sha1_t {
  uint32_t hash[5];
  uint32_t data[16];
  uint64_t num;
};

void SHA1Init(struct sha1_t *state_ptr);
void SHA1Update(struct sha1_t *state_ptr, const void *data_ptr, uint16_t num);
void SHA1Finish(struct sha1_t *state_ptr);

void SHA1BigToLittleEndian(struct sha1_t *state_ptr);

#ifdef __cplusplus
}
#endif

#endif /* __SHA1__ */
