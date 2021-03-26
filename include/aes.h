/*
 AES implementation.

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

#ifndef _AES_H_
#define _AES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#ifndef AES_KEY_LEN
#define AES_KEY_LEN 16 /* 128=>16, 192=>24, 256=>32 */
#endif

#define AES_BLOCK_LEN 16
#define AES_NUM_ROUNDS (AES_KEY_LEN / 4 + 6)
#define AES_SUBKEYS_LEN (AES_BLOCK_LEN * (AES_NUM_ROUNDS + 1))

void AES_ECBEncrypt(const uint8_t key[AES_KEY_LEN],
                    const uint8_t plain[AES_BLOCK_LEN],
                    uint8_t cipher[AES_BLOCK_LEN]);

void AES_ECBDecrypt(const uint8_t key[AES_KEY_LEN],
                    const uint8_t cipher[AES_BLOCK_LEN],
                    uint8_t plain[AES_BLOCK_LEN]);

void AES_CBCEncrypt(const uint8_t key[AES_KEY_LEN],
                    const uint8_t iv[AES_BLOCK_LEN], const uint8_t *plain_ptr,
                    uint32_t length, uint8_t *cipher_ptr);

void AES_CBCDecrypt(const uint8_t key[AES_KEY_LEN],
                    const uint8_t iv[AES_BLOCK_LEN], const uint8_t *cipher_ptr,
                    uint32_t length, uint8_t *plain_ptr);

struct aes_hash_state_t {
  uint8_t hash[AES_BLOCK_LEN];
  uint8_t plain[AES_KEY_LEN];
  uint8_t length;
};

void AESHashInit(struct aes_hash_state_t *state_ptr);
void AESHashInitIv(struct aes_hash_state_t *state_ptr,
                   const uint8_t iv[AES_BLOCK_LEN]);
void AESHashUpdate(struct aes_hash_state_t *state_ptr, const uint8_t *plain_ptr,
                   uint32_t length);
void AESHashFinish(struct aes_hash_state_t *state_ptr);

#ifdef __cplusplus
}
#endif

#endif /* _AES_H_ */
