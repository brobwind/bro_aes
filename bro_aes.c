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


#define RCON(x)	(rcon(x) << 24)


static uint8_t rcon(uint8_t i) {
    uint8_t c;

    for (c = 1; i != 1; i--)
        c = c << 1 ^ (c & 0x80 ? 0x1b : 0);

    return c;
}

// https://en.wikipedia.org/wiki/Finite_field_arithmetic
/* Multiply two numbers in the GF(2^8) finite field defined 
 * by the polynomial x^8 + x^4 + x^3 + x + 1 = 0
 * using the Russian Peasant Multiplication algorithm
 * (the other way being to do carry-less multiplication followed by a modular reduction)
 */
static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0; /* the product of the multiplication */
    while (b) {
        if (b & 1) /* if b is odd, then add the corresponding a to p (final product = sum of all a's corresponding to odd b's) */
            p ^= a; /* since we're in GF(2^m), addition is an XOR */

        if (a & 0x80) /* GF modulo: if a >= 128, then it will overflow when shifted left, so reduce */
            a = (a << 1) ^ 0x11b; /* XOR with the primitive polynomial x^8 + x^4 + x^3 + x + 1 (0b1_0001_1011) -- you can change it but it must be irreducible */
        else
            a <<= 1; /* equivalent to a*2 */
        b >>= 1; /* equivalent to b // 2 */
    }
    return p;
}

// https://en.wikipedia.org/wiki/Rijndael_S-box
static void initialize_aes_sbox(uint8_t *sbox)
{
    /* loop invariant: p * q == 1 in the Galois field */
    uint8_t p = 1, q = 1;
    do {
        /* multiply p by x+1 */
        p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);
        /* divide q by x+1 */
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= q & 0x80 ? 0x09 : 0;
        /* compute the affine transformation */
        sbox[p] = 0x63 ^ q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);
    } while (p != 1);
    /* 0 is a special case since it has no inverse */
    sbox[0] = 0x63;
}

static void initialize_aes_inv_sbox(uint8_t *inv_sbox)
{
    uint8_t sbox[256];
    int32_t i;

    initialize_aes_sbox(sbox);

    for (i = 0; i < 256; i++) inv_sbox[sbox[i]] = i;
}

int AES_set_encrypt_key(const uint8_t *userKey, const uint32_t bits, AES_KEY *key)
{
    uint32_t i, v1, v2, v3, v4, v5;

    if (bits != 128) return -1;

    key->rounds = 10;
    initialize_aes_sbox(key->sbox);

    v1 = key->rd_key[0] = *(uint32_t *)(userKey +  0);
    v2 = key->rd_key[1] = *(uint32_t *)(userKey +  4);
    v3 = key->rd_key[2] = *(uint32_t *)(userKey +  8);
    v4 = key->rd_key[3] = *(uint32_t *)(userKey + 12);

    uint8_t *sbox = key->sbox;

    for (i = 1; i <= key->rounds; i++) {
        v5 = sbox[(v4 >> 24) & 0xff] <<  0 |
                sbox[(v4 >> 16) & 0xff] << 24 |
                sbox[(v4 >>  8) & 0xff] << 16 |
                sbox[(v4 >>  0) & 0xff] <<  8;
        v1 = RCON(i) ^ v5 ^ v1;
        v2 = v1 ^ v2;
        v3 = v2 ^ v3;
        v4 = v3 ^ v4;

        key->rd_key[4 * i + 0] = v1;
        key->rd_key[4 * i + 1] = v2;
        key->rd_key[4 * i + 2] = v3;
        key->rd_key[4 * i + 3] = v4;
    }

    return 0;
}

void AES_encrypt(const uint8_t *text, uint8_t *cipher, const AES_KEY *key)
{
    uint32_t v1, v2, v3, v4;
    uint32_t v11, v12, v13, v14;
    uint32_t v17, v18, v20;

    v1 = key->rd_key[0] ^ *(uint32_t *)(text +  0);
    v2 = key->rd_key[1] ^ *(uint32_t *)(text +  4);
    v3 = key->rd_key[2] ^ *(uint32_t *)(text +  8);
    v4 = key->rd_key[3] ^ *(uint32_t *)(text + 12);

    const uint8_t *sbox = key->sbox;

    for (v20 = 1; v20 < 10; v20++) {
        v11 = sbox[(v1 >> 24) & 0xFF] << 24 | sbox[(v2 >> 16) & 0xFF] << 16 | sbox[(v3 >>  8) & 0xFF] <<  8 | sbox[(v4 >>  0) & 0xFF] <<  0;
        v12 = sbox[(v1 >>  0) & 0xFF] <<  0 | sbox[(v2 >> 24) & 0xFF] << 24 | sbox[(v3 >> 16) & 0xFF] << 16 | sbox[(v4 >>  8) & 0xFF] <<  8;
        v13 = sbox[(v1 >>  8) & 0xFF] <<  8 | sbox[(v2 >>  0) & 0xFF] <<  0 | sbox[(v3 >> 24) & 0xFF] << 24 | sbox[(v4 >> 16) & 0xFF] << 16;
        v14 = sbox[(v1 >> 16) & 0xFF] << 16 | sbox[(v2 >>  8) & 0xFF] <<  8 | sbox[(v3 >>  0) & 0xFF] <<  0 | sbox[(v4 >> 24) & 0xFF] << 24;

        /*****************************************************************************
        v1  = [ a1 a2 a3 a4 ] <- 0xa1a2a3a4
        v2  = [ b1 b2 b3 b4 ] <- 0xb1b2b3b4
        v3  = [ c1 c2 c3 c4 ] <- 0xc1c2c3c4
        v4  = [ d1 d2 d3 d4 ] <- 0xd1d2d3d4

        v11 = [ a1 b2 c3 d4 ] <- 0xa1b2c3d4
        v12 = [ b1 c2 d3 a4 ] <- 0xb1c2d3a4
        v13 = [ c1 d2 a3 b4 ] <- 0xc1d2a3b4
        v14 = [ d1 a2 b3 c4 ] <- 0xd1a2b3c4

        v1 = \
            [ 02 03 01 01 ] [ a1 ]
            [ 01 02 03 01 ] [ b2 ]
            [ 01 01 02 03 ] [ c3 ]
            [ 03 01 01 02 ] [ d4 ]
           = \
            (02*a1 ^ 03*b2 ^ 01*c3 ^ 01*d4) << 24 |        <- (02*a1 ^ 03*b2 ^ 01*c3 ^ 01*d4) << 24
            (01*a1 ^ 02*b2 ^ 03*c3 ^ 01*d4) << 16 |        <- (02*b2 ^ 03*c3 ^ 01*d1 ^ 01*a1) << 16
            (01^a1 ^ 01*b2 ^ 02*c3 ^ 03*d4) <<  8 |        <- (02*c3 ^ 03*d4 ^ 01*a1 ^ 01*b2) <<  8
            (03*a1 ^ 01*b2 ^ 01*c3 ^ 02*d4) <<  0          <- (02*d4 ^ 03*a1 ^ 01*b2 ^ 01*c3) <<  0
        --------------------------------------------------------------------------------------------

        [ 0e 0b 0d 09 ] [ 02 03 01 01 ]   [ 01 00 00 00 ]
        [ 09 0e 0b 0d ] [ 01 02 03 01 ]   [ 00 01 00 00 ]
                                        =
        [ 0d 09 0e 0b ] [ 01 01 02 03 ]   [ 00 00 01 00 ]
        [ 0b 0d 09 0e ] [ 03 01 01 02 ]   [ 00 00 00 01 ]
        *****************************************************************************/
        v17 = ROTATE(v11, 16);
        v18 = ROTATE(v11, 24);
        v1 = key->rd_key[4 * v20 + 0] ^ 0x1B * ((v11 >> 7) & 0x1010101) ^ 2 * (v11 & 0xFF7F7F7F) ^
                ((2 * (v11 & 0x7F000000) ^ 0x1B * ((v11 >> 7) & 0x1010101) ^ v11) >> 24 | (0x1B * ((v11 >> 7) & 0x10101) ^ 2 * (v11 & 0xFFFF7F7F) ^ v11) << 8) ^ v18 ^ v17;

        v17 = ROTATE(v12, 16);
        v18 = ROTATE(v12, 24);
        v2 = key->rd_key[4 * v20 + 1] ^ 0x1B * ((v12 >> 7) & 0x1010101) ^ 2 * (v12 & 0xFF7F7F7F) ^
                ((2 * (v12 & 0x7F000000) ^ 0x1B * ((v12 >> 7) & 0x1010101) ^ v12) >> 24 | (0x1B * ((v12 >> 7) & 0x10101) ^ 2 * (v12 & 0xFFFF7F7F) ^ v12) << 8) ^ v18 ^ v17;

        v17 = ROTATE(v13, 16);
        v18 = ROTATE(v13, 24);
        v3 = key->rd_key[4 * v20 + 2] ^ 0x1B * ((v13 >> 7) & 0x1010101) ^ 2 * (v13 & 0xFF7F7F7F) ^
                ((2 * (v13 & 0x7F000000) ^ 0x1B * ((v13 >> 7) & 0x1010101) ^ v13) >> 24 | (0x1B * ((v13 >> 7) & 0x10101) ^ 2 * (v13 & 0xFFFF7F7F) ^ v13) << 8) ^ v18 ^ v17;

        v17 = ROTATE(v14, 16);
        v18 = ROTATE(v14, 24);
        v4 = key->rd_key[4 * v20 + 3] ^ 0x1B * ((v14 >> 7) & 0x1010101) ^ 2 * (v14 & 0xFF7F7F7F) ^
                ((2 * (v14 & 0x7F000000) ^ 0x1B * ((v14 >> 7) & 0x1010101) ^ v14) >> 24 | (0x1B * ((v14 >> 7) & 0x10101) ^ 2 * (v14 & 0xFFFF7F7F) ^ v14) << 8) ^ v18 ^ v17;
    }

    // v1 v2, v3, v4
    *(uint32_t *)(cipher +  0) = key->rd_key[4 * v20 + 0] ^
            (sbox[(v1 >> 24) & 0xFF] << 24 | sbox[(v2 >> 16) & 0xFF] << 16 | sbox[(v3 >>  8) & 0xFF] <<  8 | sbox[(v4 >>  0) & 0xFF] <<  0);

    *(uint32_t *)(cipher +  4) = key->rd_key[4 * v20 + 1] ^
            (sbox[(v1 >>  0) & 0xFF] <<  0 | sbox[(v2 >> 24) & 0xFF] << 24 | sbox[(v3 >> 16) & 0xFF] << 16 | sbox[(v4 >>  8) & 0xFF] <<  8);

    *(uint32_t *)(cipher +  8) = key->rd_key[4 * v20 + 2] ^
            (sbox[(v1 >>  8) & 0xFF] <<  8 | sbox[(v2 >>  0) & 0xFF] <<  0 | sbox[(v3 >> 24) & 0xFF] << 24 | sbox[(v4 >> 16) & 0xFF] << 16);

    *(uint32_t *)(cipher + 12) = key->rd_key[4 * v20 + 3] ^
            (sbox[(v1 >> 16) & 0xFF] << 16 | sbox[(v2 >>  8) & 0xFF] <<  8 | sbox[(v3 >>  0) & 0xFF] <<  0 | sbox[(v4 >> 24) & 0xFF] << 24);
}

int AES_set_decrypt_key(const uint8_t *userKey, const uint32_t bits, AES_KEY *key)
{
    uint32_t i, v1, v2, v3, v4, v5;

    if (bits != 128) return -1;

    key->rounds = 10;
    initialize_aes_sbox(key->sbox);

    v1 = key->rd_key[0] = *(uint32_t *)(userKey +  0);
    v2 = key->rd_key[1] = *(uint32_t *)(userKey +  4);
    v3 = key->rd_key[2] = *(uint32_t *)(userKey +  8);
    v4 = key->rd_key[3] = *(uint32_t *)(userKey + 12);

    uint8_t *sbox = key->sbox;

    for (i = 1; i <= key->rounds; i++) {
        v5 = sbox[(v4 >> 24) & 0xff] <<  0 |
                sbox[(v4 >> 16) & 0xff] << 24 |
                sbox[(v4 >>  8) & 0xff] << 16 |
                sbox[(v4 >>  0) & 0xff] <<  8;
        v1 = RCON(i) ^ v5 ^ v1;
        v2 = v1 ^ v2;
        v3 = v2 ^ v3;
        v4 = v3 ^ v4;

        key->rd_key[4 * i + 0] = v1;
        key->rd_key[4 * i + 1] = v2;
        key->rd_key[4 * i + 2] = v3;
        key->rd_key[4 * i + 3] = v4;
    }

    initialize_aes_inv_sbox(key->sbox);

    return 0;
}

void AES_decrypt(const uint8_t *cipher, uint8_t *text, const AES_KEY *key)
{
    uint32_t v1, v2, v3, v4, v11, v12, v13, v14;
    const uint8_t *inv_sbox = key->sbox;
    uint32_t v20 = key->rounds;

    v11 = *(uint32_t *)(cipher +  0) ^ key->rd_key[v20 * 4 + 0];
    v12 = *(uint32_t *)(cipher +  4) ^ key->rd_key[v20 * 4 + 1];
    v13 = *(uint32_t *)(cipher +  8) ^ key->rd_key[v20 * 4 + 2];
    v14 = *(uint32_t *)(cipher + 12) ^ key->rd_key[v20 * 4 + 3];

    v1 = inv_sbox[(v11 >> 24) & 0xff] << 24 |
         inv_sbox[(v14 >> 16) & 0xff] << 16 |
         inv_sbox[(v13 >>  8) & 0xff] <<  8 |
         inv_sbox[(v12 >>  0) & 0xff] <<  0;

    v2 = inv_sbox[(v12 >> 24) & 0xff] << 24 |
         inv_sbox[(v11 >> 16) & 0xff] << 16 |
         inv_sbox[(v14 >>  8) & 0xff] <<  8 |
         inv_sbox[(v13 >>  0) & 0xff] <<  0;

    v3 = inv_sbox[(v13 >> 24) & 0xff] << 24 |
         inv_sbox[(v12 >> 16) & 0xff] << 16 |
         inv_sbox[(v11 >>  8) & 0xff] <<  8 |
         inv_sbox[(v14 >>  0) & 0xff] <<  0;

    v4 = inv_sbox[(v14 >> 24) & 0xff] << 24 |
         inv_sbox[(v13 >> 16) & 0xff] << 16 |
         inv_sbox[(v12 >>  8) & 0xff] <<  8 |
         inv_sbox[(v11 >>  0) & 0xff] <<  0;

    for (v20--; v20 >= 1; v20--) {
        uint32_t *v30[4] = { &v1, &v2, &v3, &v4 };
        uint8_t a1, a2, a3, a4;
        int32_t i;
        /************************************************************************
        v1 = 0xa1a2a3a4
        v11 = \
                [ 0e 0b 0d 09 ]   [ a1 ]
                [ 09 0e 0b 0d ]   [ a2 ]
                [ 0d 09 0e 0b ]   [ a3 ]
                [ 0b 0d 09 0e ]   [ a4 ]
            = \
                (0e*a1 ^ 0b*a2 ^ 0d*a3 ^ 09*a4) << 24 |
                (09*a1 ^ 0e*a2 ^ 0b*a3 ^ 0d*a4) << 16 |
                (0d*a1 ^ 09*a2 ^ 0e*a3 ^ 0b*a4) <<  8 |
                (0b*a1 ^ 0d*a2 ^ 09*a3 ^ 0e*a4) <<  0
        *************************************************************************/
        for (i = 0; i < 4; i++) {
            uint32_t *v = v30[i];
            *v ^= key->rd_key[4 * v20 + i];

            a1 = (*v >> 24) & 0xff;
            a2 = (*v >> 16) & 0xff;
            a3 = (*v >>  8) & 0xff;
            a4 = (*v >>  0) & 0xff;

            *v = (gmul(a1, 0x0e) ^ gmul(a2, 0x0b) ^ gmul(a3, 0x0d) ^ gmul(a4, 0x09)) << 24 |
                     (gmul(a1, 0x09) ^ gmul(a2, 0x0e) ^ gmul(a3, 0x0b) ^ gmul(a4, 0x0d)) << 16 |
                     (gmul(a1, 0x0d) ^ gmul(a2, 0x09) ^ gmul(a3, 0x0e) ^ gmul(a4, 0x0b)) <<  8 |
                     (gmul(a1, 0x0b) ^ gmul(a2, 0x0d) ^ gmul(a3, 0x09) ^ gmul(a4, 0x0e)) <<  0;
        }
        
        v11 = inv_sbox[(v1 >> 24) & 0xff] << 24 |
             inv_sbox[(v4 >> 16) & 0xff] << 16 |
             inv_sbox[(v3 >>  8) & 0xff] <<  8 |
             inv_sbox[(v2 >>  0) & 0xff] <<  0;

        v12 = inv_sbox[(v2 >> 24) & 0xff] << 24 |
             inv_sbox[(v1 >> 16) & 0xff] << 16 |
             inv_sbox[(v4 >>  8) & 0xff] <<  8 |
             inv_sbox[(v3 >>  0) & 0xff] <<  0;

        v13 = inv_sbox[(v3 >> 24) & 0xff] << 24 |
             inv_sbox[(v2 >> 16) & 0xff] << 16 |
             inv_sbox[(v1 >>  8) & 0xff] <<  8 |
             inv_sbox[(v4 >>  0) & 0xff] <<  0;

        v14 = inv_sbox[(v4 >> 24) & 0xff] << 24 |
             inv_sbox[(v3 >> 16) & 0xff] << 16 |
             inv_sbox[(v2 >>  8) & 0xff] <<  8 |
             inv_sbox[(v1 >>  0) & 0xff] <<  0;

        v1 = v11; v2 = v12; v3 = v13; v4 = v14;
    }

    *(uint32_t *)(text +  0) = key->rd_key[0] ^ v1;
    *(uint32_t *)(text +  4) = key->rd_key[1] ^ v2;
    *(uint32_t *)(text +  8) = key->rd_key[2] ^ v3;
    *(uint32_t *)(text + 12) = key->rd_key[3] ^ v4;
}
