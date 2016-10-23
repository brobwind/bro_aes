# bro_aes
An AES 128-bit encryption/decryption library suitable for embed system or study

1. Implement standard AES 128-bit algorithm, then can produce the same result as openssl
2. Add more comments to explain the algorithm.

Add a macro to support this function:
	$ STANDARD_AS_OPENSSL=1 make

```bash
$ ./bro_aes 
 --------------------- AES 128 ENC EXPANDED KEY -------------------------
00000000: 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c  +~..(.........O<
00000010: c0 7f 9f 93 e8 d1 4d 35 43 26 58 bd 4a e9 17 81  ......M5C&X.J...
00000020: cc a9 81 61 24 78 cc 54 67 5e 94 e9 2d b7 83 68  ...a$x.Tg^..-..h
00000030: 89 71 28 89 ad 09 e4 dd ca 57 70 34 e7 e0 f3 5c  .q(......Wp4...\
00000040: c3 e5 c9 8c 6e ec 2d 51 a4 bb 5d 65 43 5b ae 39  ....n.-Q..]eC[.9
00000050: d1 ff f0 78 bf 13 dd 29 1b a8 80 4c 58 f3 2e 75  ...x...)...LX..u
00000060: 4c 95 fd 69 f3 86 20 40 e8 2e a0 0c b0 dd 8e 79  L..i.. @.......y
00000070: fa 72 3c 30 09 f4 1c 70 e1 da bc 7c 51 07 32 05  .r<0...p...|Q.2.
00000080: 91 a3 f9 93 98 57 e5 e3 79 8d 59 9f 28 8a 6b 9a  .....W..y.Y.(.k.
00000090: 29 97 87 f7 b1 c0 62 14 c8 4d 3b 8b e0 c7 50 11  ).....b..M;...P.
000000a0: ab 76 41 92 1a b6 23 86 d2 fb 18 0d 32 3c 48 1c  .vA...#.....2<H.
 --------------------- AES 128 ENC - CIPHER -----------------------------
00000000: b6 08 04 bc 5f 65 f2 b3 d7 16 f7 6f d6 6a a2 27  ...._e.....o.j.'
 --------------------- AES 128 DEC EXPANDED KEY -------------------------
00000000: 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c  +~..(.........O<
00000010: c0 7f 9f 93 e8 d1 4d 35 43 26 58 bd 4a e9 17 81  ......M5C&X.J...
00000020: cc a9 81 61 24 78 cc 54 67 5e 94 e9 2d b7 83 68  ...a$x.Tg^..-..h
00000030: 89 71 28 89 ad 09 e4 dd ca 57 70 34 e7 e0 f3 5c  .q(......Wp4...\
00000040: c3 e5 c9 8c 6e ec 2d 51 a4 bb 5d 65 43 5b ae 39  ....n.-Q..]eC[.9
00000050: d1 ff f0 78 bf 13 dd 29 1b a8 80 4c 58 f3 2e 75  ...x...)...LX..u
00000060: 4c 95 fd 69 f3 86 20 40 e8 2e a0 0c b0 dd 8e 79  L..i.. @.......y
00000070: fa 72 3c 30 09 f4 1c 70 e1 da bc 7c 51 07 32 05  .r<0...p...|Q.2.
00000080: 91 a3 f9 93 98 57 e5 e3 79 8d 59 9f 28 8a 6b 9a  .....W..y.Y.(.k.
00000090: 29 97 87 f7 b1 c0 62 14 c8 4d 3b 8b e0 c7 50 11  ).....b..M;...P.
000000a0: ab 76 41 92 1a b6 23 86 d2 fb 18 0d 32 3c 48 1c  .vA...#.....2<H.
 --------------------- AES 128 DEC - TEXT -------------------------------
00000000: 77 77 77 2e 62 72 6f 62 77 69 6e 64 2e 63 6f 6d  www.brobwind.com
```

For detail info, please refer:

1. https://www.brobwind.com/archives/1236
2. https://www.brobwind.com/archives/1255

