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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bro_aes.h"


#define RCON(x)                            (rcon(x) << 24)

#if STANDARD_AS_OPENSSL == 1
#define SWAP(x)                            __builtin_bswap32(x)
#else
#define SWAP(x)                            (x)
#endif


static uint8_t rcon(uint8_t i) {
    uint8_t c;

    for (c = 1; i != 1; i--)
        c = c << 1 ^ (c & 0x80 ? 0x1b : 0);

    return c;
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

    v1 = key->rd_key[0] = SWAP(*(uint32_t *)(userKey +  0));
    v2 = key->rd_key[1] = SWAP(*(uint32_t *)(userKey +  4));
    v3 = key->rd_key[2] = SWAP(*(uint32_t *)(userKey +  8));
    v4 = key->rd_key[3] = SWAP(*(uint32_t *)(userKey + 12));

    uint8_t *sbox = key->sbox;

    for (i = 1; i <= (uint32_t)key->rounds; i++) {
        v5 = sbox[(v4 >> 24) & 0xff] <<  0 |
                sbox[(v4 >> 16) & 0xff] << 24 |
                sbox[(v4 >>  8) & 0xff] << 16 |
                sbox[(v4 >>  0) & 0xff] <<  8;
        key->rd_key[4 * i + 0] = v1 = RCON(i) ^ v5 ^ v1;
        key->rd_key[4 * i + 1] = v2 = v1 ^ v2;
        key->rd_key[4 * i + 2] = v3 = v2 ^ v3;
        key->rd_key[4 * i + 3] = v4 = v3 ^ v4;
    }

    return 0;
}

static uint32_t AES_encrypt_one_row_opt(uint32_t v1)
{
    uint32_t v2, v3, v4, v5, v6;

    v2 = ROTATE(v1, 16);
    v3 = ROTATE(v1, 24);
    v4 = ((v1 & 0xFF7F7F7F) * 2) ^ (((v1 >> 7) & 0x01010101) * 0x1B);
    v5 = ((v1 & 0x7F000000) * 2) ^ (((v1 >> 7) & 0x01010101) * 0x1B);
    v6 = ((v1 & 0xFFFF7F7F) * 2) ^ (((v1 >> 7) & 0x00010101) * 0x1B);

    return v2 ^ v3 ^ v4 ^ ((v5 ^ v1) >> 24 | (v6 ^ v1) << 8);
}

void AES_encrypt(const uint8_t *text, uint8_t *cipher, const AES_KEY *key)
{
    int32_t v20;
    uint32_t v1, v2, v3, v4, v11, v12, v13, v14;
    const uint8_t *sbox = key->sbox;

    v11 = SWAP(*(uint32_t *)(text +  0));
    v12 = SWAP(*(uint32_t *)(text +  4));
    v13 = SWAP(*(uint32_t *)(text +  8));
    v14 = SWAP(*(uint32_t *)(text + 12));

    for (v20 = 0; v20 <= key->rounds; v20++) {
        v1 = key->rd_key[4 * v20 + 0] ^ v11;
        v2 = key->rd_key[4 * v20 + 1] ^ v12;
        v3 = key->rd_key[4 * v20 + 2] ^ v13;
        v4 = key->rd_key[4 * v20 + 3] ^ v14;

        if (v20 < key->rounds) {
            v11 = sbox[(v1 >> 24) & 0xFF] << 24 | sbox[(v2 >> 16) & 0xFF] << 16 | sbox[(v3 >>  8) & 0xFF] <<  8 | sbox[(v4 >>  0) & 0xFF] <<  0;
            v12 = sbox[(v1 >>  0) & 0xFF] <<  0 | sbox[(v2 >> 24) & 0xFF] << 24 | sbox[(v3 >> 16) & 0xFF] << 16 | sbox[(v4 >>  8) & 0xFF] <<  8;
            v13 = sbox[(v1 >>  8) & 0xFF] <<  8 | sbox[(v2 >>  0) & 0xFF] <<  0 | sbox[(v3 >> 24) & 0xFF] << 24 | sbox[(v4 >> 16) & 0xFF] << 16;
            v14 = sbox[(v1 >> 16) & 0xFF] << 16 | sbox[(v2 >>  8) & 0xFF] <<  8 | sbox[(v3 >>  0) & 0xFF] <<  0 | sbox[(v4 >> 24) & 0xFF] << 24;
        }

        if (v20 < key->rounds - 1) {
            v11 = AES_encrypt_one_row_opt(v11);
            v12 = AES_encrypt_one_row_opt(v12);
            v13 = AES_encrypt_one_row_opt(v13);
            v14 = AES_encrypt_one_row_opt(v14);
        }

        /*******************************************************************************************
        Standard Algorithm(As OpenSSL):
        =============================================================
        Initial:
        -------------------------------------------
        - Plain Text
        s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, sa, sb, sc, sd, se, sf
        - Round Key
        r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, ra, rb, rc, rd, re, rf

        Layout & Sub Bytes:
        ----------------------------------------------
        [ s0, s4, s8, sc ]
        [ s1, s5, s9, sd ]
        [ s2, s6, sa, se ]
        [ s3, s7, sb, sf ]

        Shift Rows:
        --------------------------------------
        [ s0, s4, s8, sc ]
        [ s5, s9, sd, s1 ] <- (Shift 1 byte)
        [ sa, se, s2, s6 ] <- (Shift 2 bytes)
        [ sf, s3, s7, sb ] <- (Shift 3 bytes)

        Mix Columns:
        -------------------------------------
        [ 2 3 1 1 ] [ s0, s4, s8, sc ]
        [ 1 2 3 1 ]*[ s5, s9, sd, s1 ]
        [ 1 1 2 3 ] [ sa, se, s2, s6 ]
        [ 3 1 1 2 ] [ sf, s3, s7, sb ]

        - 1. 1st column
        [ 2*s0 ^ 3*s5 ^ 1*sa ^ 1*sf ] <- S0
        [ 1*s0 ^ 2*s5 ^ 3*sa ^ 1*sf ] <- S5
        [ 1*s0 ^ 1*s5 ^ 2*sa ^ 3*sf ] <- SA
        [ 3*s0 ^ 1*s5 ^ 1*sf ^ 2*sf ] <- SF

        - 2. 2, 3, 4 columns
        ...

        - 3. Finally:
        [ S0, S4, S8, SC ]
        [ S5, S9, SD, S1 ]
        [ SA, SE, S2, S6 ]
        [ SF, S3, S7, SB ]

        Add Round Key:
        --------------------------------------
        [ S0 ^ r0, S4 ^ r4, S8 ^ r8, SC ^ rc ]
        [ S5 ^ r1, S9 ^ r5, SD ^ r9, S1 ^ rd ]
        [ SA ^ r2, SE ^ r6, S2 ^ ra, S6 ^ re ]
        [ SF ^ r3, S3 ^ r7, S7 ^ rb, SB ^ rf ]

        Implementation:
        ===========================================                  =====================================
        Initial:
        -------------------------------------------
        - Plain Text:
        s0, s1, s2, s3, s4, s5, s6, s7,                              s3, s2, s1, s0, s7, s6, s5, s4,
        s8, s9, sa, sb, sc, sd, se, sf                               sb, sa, s9, s8, sf, se, sd, sc
        - Round Key:
        r0, r1, r2, r3, r4, r5, r6, r7,                              r3, r2, r1, r0, r7, r6, r5, r4,
        r8, r9, ra, rb, rc, rd, re, rf                               rb, ra, r9, r8, rf, re, rd, rc

           /- v1 0xs3s2s1s0                                              /- v1 0xs0s1s2s3
           |   /- v2 0xs7s6s5s4                                          |   /- v2 0xs4s5s6s7
           |   |   /- v3 0xsbsas9s8                                      |   |   /- v3 0xs8s9sasb
           |   |   |   /- v4 0xsfsesds                                   |   |   |   /- v4 0xscsdsesf
        [ s0, s4, s8, sc ]                                            [ s3, s7, sb, sf ]
        [ s1, s5, s9, sd ]                                            [ s2, s6, sa, se ]
        [ s2, s6, sa, se ]                                            [ s1, s5, s9, sd ]
        [ s3, s7, sb, sf ]                                            [ s0, s4, s8, sc ]

        Sub Bytes & Shift Rows:
        --------------------------------------                        -------------------------------------
        [ sc, s0, s4, s8 ] <- (Shift 3 bytes)                         [ sf, s3, s7, sb ] <- (Shift 3 bytes)
        [ s9, sd, s1, s5 ] <- (Shift 2 bytes)                         [ sa, se, s2, s6 ] <- (Shift 2 bytes)
        [ s6, sa, se, s2 ] <- (Shift 1 byte)                          [ s5, s9, sd, s1 ] <- (Shift 1 byte)
        [ s3, s7, sb, sf ]                                            [ s0, s4, s8, sc ]
           |   |   |   `- v14 0xsfs2s5s8                                 |   |   |   `- v14 0xscs1s6sb
           |   |   `- v13 0xsbses1s4                                     |   |   `- v13 0xs8sds2s7
           |   `- v12 0xs7sasds0                                         |   `- v12 0xs4s9ses3
           `- v11 0xs3s6s9sc                                             `- v11 0xs0s5sasf

        Mix Columns:
        -------------------------------------                         -------------------------------------
        [ 2 3 1 1 ] [ sc, s0, s4, s8 ]                            [ 2 3 1 1 ] [ sf, s3, s7, sb ]
        [ 1 2 3 1 ]*[ s9, sd, s1, s5 ]                            [ 1 2 3 1 ]*[ sa, se, s2, s6 ]
        [ 1 1 2 3 ] [ s6, sa, se, s2 ]                            [ 1 1 2 3 ] [ s5, s9, sd, s1 ]
        [ 3 1 1 2 ] [ s3, s7, sb, sf ]                            [ 3 1 1 2 ] [ s0, s4, s8, sc ]
                           |   |   |   `- v14 0xsfs2s5s8                                 |   |   |   `- v14 0xscs1s6sb
                           |   |   `- v13 0xsbses1s4                                     |   |   `- v13 0xs8sds2s7
                           |   `- v12 0xs7sasds0                                         |   `- v12 0xs4s9ses3
                           `- v11 0xs3s6s9sc                                             `- v11 0xs0s5sasf
        - 1. 1st column
        v1 = \
            (2*s3 ^ 3*s6 ^ 1*s9 ^ 1*sc) << 24 |                   (2*s0 ^ 3*s5 ^ 1*sa ^ 1*sf) << 24 |  <- (S0 << 24)
            (1*s3 ^ 2*s6 ^ 3*s9 ^ 1*sc) << 16 |                   (1*s0 ^ 2*s5 ^ 3*sa ^ 1*sf) << 16 |  <- (S5 << 16)
            (1*s3 ^ 1*s6 ^ 2*s9 ^ 3*sc) <<  8 |                   (1*s0 ^ 1*s5 ^ 2*sa ^ 3*sf) <<  8 |  <- (SA <<  8)
            (3*s3 ^ 1*s6 ^ 1*s9 ^ 2*sc) <<  0                     (3*s0 ^ 1*s5 ^ 1*sf ^ 2*sf) <<  0    <- (SF <<  0)

        - 2. 2, 3, 4 columns
        ...

        - 3. Finally:
        [ SC, S0, S4, S8 ]                                             [ SF, S3, S7, SB ]
        [ S9, SD, S1, S5 ]                                             [ SA, SE, S2, S6 ]
        [ S6, SA, SE, S2 ]                                             [ S5, S9, SD, S1 ]
        [ S3, S7, SB, SF ]                                             [ S0, S4, S8, SC ]
          |    |   |   `- v4 0xSFS2S5S8                                   |    |   |   `- v4 0xSCS1S6SB
          |    |   `- v3 0xSBSES1S4                                       |    |   `- v3 0xS8SDS2S7
          |    `- v2 0xS7SASDS0                                           |    `- v2 0xS4S9SES3
          `- v1 0xS3S6S9SC                                                `- v1 0xS0S5SASF

        Add Round Key:
        --------------------------------------
        [ SC ^ r0, S0 ^ r4, S4 ^ r8, S8 ^ rc ]                         [ SF ^ r3, S3 ^ r7, S7 ^ rb, SB ^ rf ]
        [ S9 ^ r1, SD ^ r5, S1 ^ r9, S5 ^ rd ]                         [ SA ^ r2, SE ^ r6, S2 ^ ra, S6 ^ re ]
        [ S6 ^ r2, SA ^ r6, SE ^ ra, S2 ^ re ]                         [ S5 ^ r1, S9 ^ r5, SD ^ r9, S1 ^ rd ]
        [ S3 ^ r3, S7 ^ r7, SB ^ rb, SF ^ rf ]                         [ S0 ^ r0, S4 ^ r4, S8 ^ r8, SC ^ rc ]
        *******************************************************************************************/
    }

    // v1 v2, v3, v4
    *(uint32_t *)(cipher +  0) = SWAP(v1);
    *(uint32_t *)(cipher +  4) = SWAP(v2);
    *(uint32_t *)(cipher +  8) = SWAP(v3);
    *(uint32_t *)(cipher + 12) = SWAP(v4);
}

int AES_set_decrypt_key(const uint8_t *userKey, const uint32_t bits, AES_KEY *key)
{
    if (bits != 128) return -1;

    AES_set_encrypt_key(userKey, bits, key);
    initialize_aes_inv_sbox(key->sbox);

    return 0;
}

static uint32_t AES_decrypt_one_row_opt(uint32_t v1)
{
    uint32_t v2, v3, v4, v5, v6, v7;

    v2 = ((v1 & 0xFF7F7F7F) * 2) ^ (((v1 >> 7) & 0x01010101) * 0x1B);
    v3 = ((v2 & 0xFF7F7F7F) * 2) ^ (((v2 >> 7) & 0x01010101) * 0x1B);
    v4 = ((v3 & 0xFF7F7F7F) * 2) ^ (((v3 >> 7) & 0x01010101) * 0x1B);

    v5 = ROTATE(v1 ^ v2 ^ v4, 8);
    v6 = ROTATE(v1 ^ v3 ^ v4, 16);
    v7 = ROTATE(v1 ^ v4, 24);

    return v2 ^ v3 ^ v4 ^ v5 ^ v6 ^ v7;
}

void AES_decrypt(const uint8_t *cipher, uint8_t *text, const AES_KEY *key)
{
    uint32_t v1, v2, v3, v4, v11, v12, v13, v14;
    int32_t v20 = key->rounds;
    const uint8_t *inv_sbox = key->sbox;

    v1 = SWAP(*(uint32_t *)(cipher +  0)) ^ key->rd_key[v20 * 4 + 0];
    v2 = SWAP(*(uint32_t *)(cipher +  4)) ^ key->rd_key[v20 * 4 + 1];
    v3 = SWAP(*(uint32_t *)(cipher +  8)) ^ key->rd_key[v20 * 4 + 2];
    v4 = SWAP(*(uint32_t *)(cipher + 12)) ^ key->rd_key[v20 * 4 + 3];

    for (v20--; v20 >= 0; v20--) {
        v11 = key->rd_key[v20 * 4 + 0] ^ (
             inv_sbox[(v1 >> 24) & 0xff] << 24 |
             inv_sbox[(v4 >> 16) & 0xff] << 16 |
             inv_sbox[(v3 >>  8) & 0xff] <<  8 |
             inv_sbox[(v2 >>  0) & 0xff] <<  0);

        v12 = key->rd_key[v20 * 4 + 1] ^ (
             inv_sbox[(v2 >> 24) & 0xff] << 24 |
             inv_sbox[(v1 >> 16) & 0xff] << 16 |
             inv_sbox[(v4 >>  8) & 0xff] <<  8 |
             inv_sbox[(v3 >>  0) & 0xff] <<  0);

        v13 = key->rd_key[v20 * 4 + 2] ^ (
             inv_sbox[(v3 >> 24) & 0xff] << 24 |
             inv_sbox[(v2 >> 16) & 0xff] << 16 |
             inv_sbox[(v1 >>  8) & 0xff] <<  8 |
             inv_sbox[(v4 >>  0) & 0xff] <<  0);

        v14 = key->rd_key[v20 * 4 + 3] ^ (
             inv_sbox[(v4 >> 24) & 0xff] << 24 |
             inv_sbox[(v3 >> 16) & 0xff] << 16 |
             inv_sbox[(v2 >>  8) & 0xff] <<  8 |
             inv_sbox[(v1 >>  0) & 0xff] <<  0);

        /************************************************************************
        v1 = 0xa1a2a3a4
        v11 = \
                [ 0x0e 0x0b 0x0d 0x09 ]   [ a1 ]
                [ 0x09 0x0e 0x0b 0x0d ]   [ a2 ]
                [ 0x0d 0x09 0x0e 0x0b ]   [ a3 ]
                [ 0x0b 0x0d 0x09 0x0e ]   [ a4 ]
            = \
                (0x0e*a1 ^ 0x0b*a2 ^ 0x0d*a3 ^ 0x09*a4) << 24 |
                (0x09*a1 ^ 0x0e*a2 ^ 0x0b*a3 ^ 0x0d*a4) << 16 |
                (0x0d*a1 ^ 0x09*a2 ^ 0x0e*a3 ^ 0x0b*a4) <<  8 |
                (0x0b*a1 ^ 0x0d*a2 ^ 0x09*a3 ^ 0x0e*a4) <<  0
        *************************************************************************/
        if (v20 > 0) {
            v1 = AES_decrypt_one_row_opt(v11);
            v2 = AES_decrypt_one_row_opt(v12);
            v3 = AES_decrypt_one_row_opt(v13);
            v4 = AES_decrypt_one_row_opt(v14);
        }
    }

    *(uint32_t *)(text +  0) = SWAP(v11);
    *(uint32_t *)(text +  4) = SWAP(v12);
    *(uint32_t *)(text +  8) = SWAP(v13);
    *(uint32_t *)(text + 12) = SWAP(v14);
}
