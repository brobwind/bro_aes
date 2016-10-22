/*
 * Copyright (C) 2016 https://www.brobwind.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __BRO_AES_H__
#define __BRO_AES_H__


#define AES_MAXNR        10
#define ROTL8(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))

#undef ROTATE
#if defined(_MSC_VER) || defined(__ICC)
# define ROTATE(a,n)    _lrotl(a,n)
#elif defined(__GNUC__) && __GNUC__>=2
# if defined(__i386) || defined(__i386__) || defined(__x86_64) || defined(__x86_64__)
#   define ROTATE(a,n)    ({ register unsigned int ret;    \
                asm (            \
                "roll %1,%0"        \
                : "=r"(ret)        \
                : "I"(n), "0"(a)    \
                : "cc");        \
               ret;                \
            })
# elif defined(__arm__)
// ftp://ftp.dca.fee.unicamp.br/pub/docs/ea871/ARM/ARMGCCInlineAssemblerCookbook.pdf
#   define ROTATE(a,n)   ({ register unsigned int ret;    \
                asm (            \
                "ror %0,%0,%1"        \
                : "=r"(ret)        \
                : "I"(32 - n), "0"(a)    \
                : "cc");        \
               ret;                \
            })
# endif
#endif

typedef struct {
    uint32_t rd_key[4 * (AES_MAXNR + 1)];
    int32_t rounds;
    uint8_t sbox[256];
} AES_KEY;

int AES_set_encrypt_key(const uint8_t *userKey, const uint32_t bits, AES_KEY *key);
void AES_encrypt(const uint8_t *text, uint8_t *cipher, const AES_KEY *key);

int AES_set_decrypt_key(const uint8_t *userKey, const uint32_t bits, AES_KEY *key);
void AES_decrypt(const uint8_t *cipher, uint8_t *text, const AES_KEY *key);

#endif
