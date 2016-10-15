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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bro_aes.h"
#include "bro_util.h"


int main(int argc, char *argv[])
{
    // http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
    // Expansion of a 128-bit Cipher Key
    uint8_t userKey[] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    uint8_t text[] = {
        'w', 'w', 'w', '.', 'b', 'r', 'o', 'b', 'w', 'i', 'n', 'd', '.', 'c', 'o', 'm'
    };
    uint8_t cipher[16];
    AES_KEY aes_key;

    memset(&aes_key, 0x00, sizeof(aes_key));

    AES_set_encrypt_key(userKey, 128, &aes_key);
    printf(" --------------------- AES 128 ENC EXPANDED KEY -------------------------\n");
    hexdump(aes_key.rd_key, sizeof(aes_key.rd_key), 0, NULL);

    AES_encrypt(text, cipher, &aes_key);
    printf(" --------------------- AES 128 ENC - CIPHER -----------------------------\n");
    hexdump(cipher, sizeof(cipher), 0, NULL);

    AES_set_decrypt_key(userKey, 128, &aes_key);
    printf(" --------------------- AES 128 DEC EXPANDED KEY -------------------------\n");
    hexdump(aes_key.rd_key, sizeof(aes_key.rd_key), 0, NULL);

    memset(text, 0x00, sizeof(text));

    AES_decrypt(cipher, text, &aes_key);
    printf(" --------------------- AES 128 DEC - TEXT -------------------------------\n");
    hexdump(text, sizeof(text), 0, NULL);

    return 0;
}
