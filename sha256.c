/**********************************************************************
 * Copyright (c) 2020 Dylan Sharhon                                   *
 * Distributed under the LGPL software license, see the accompanying  *
 * file LICENSE or https://choosealicense.com/licenses/lgpl-3.0/      *
 **********************************************************************/

#ifndef SHA256_C
#define SHA256_C

#include <stdint.h>
#define byte uint8_t
#define word uint32_t

/* Safe right rotate */
#define ROTR(x, n) ((x >> n) | (x << (-n & 31)))

/* Initialize array of round constants (first 32 bits of the fractional parts of
 * the cube roots of the first 64 primes)
 */
static const word SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* Process the message in successive 512-bit chunks */
static void sha256_chunk(word hash[8], const byte chunk[64]) {

	/* Create a 64-entry message schedule array w[0..63] of 32-bit words */
	word w[64];

	/* Put the padded message into the first 16 words */
	int i = 0; while (i < 16) {
		w[i] = (word)(chunk[i * 4 + 0]) << 0x18
			 | (word)(chunk[i * 4 + 1]) << 0x10
			 | (word)(chunk[i * 4 + 2]) << 0x08
			 | (word)(chunk[i * 4 + 3]) << 0x00;
        i++;
	}

	/* Extend the first 16 words into the remaining 48 words w[16..63] of the
     * message schedule array
     */
    i = 16; while (i < 64) {
		word s0 = ROTR(w[i - 15],  7) ^ ROTR(w[i - 15], 18) ^ (w[i - 15] >>  3);
		word s1 = ROTR(w[i -  2], 17) ^ ROTR(w[i -  2], 19) ^ (w[i -  2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        i++;
	}

	/* Initialize working variables to current hash value */
    word a = hash[0];
    word b = hash[1];
    word c = hash[2];
    word d = hash[3];
    word e = hash[4];
    word f = hash[5];
    word g = hash[6];
    word h = hash[7];

    /* Compression function main loop */
    i = 0; while (i < 64) {
		word S1    = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
        word ch    = (e & f) ^ ((~e) & g);
        word temp1 = h + S1 + ch + SHA256_K[i] + w[i];
        word S0    = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
        word maj   = (a & b) ^ (a & c) ^ (b & c);
        word temp2 = S0 + maj;

		/* Update working variables */
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;

        i++;
    }

    /* Add the compressed chunk to the current hash value */
    hash[0] = hash[0] + a;
    hash[1] = hash[1] + b;
    hash[2] = hash[2] + c;
    hash[3] = hash[3] + d;
    hash[4] = hash[4] + e;
    hash[5] = hash[5] + f;
    hash[6] = hash[6] + g;
    hash[7] = hash[7] + h;
}

/* Pre-process, chunk, hash, and digest a short message using SHA-256 */
void sha256(byte digest[32], const byte* msg, const int msg_len) {

	/* Initialize hash words to seed constants */
	word hash[8] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	};

    /* Chunk and hash the message, "padding" the last chunk to 512 bits */

    /* "Append a single '1' bit, K '0' bits, and a 64-bit message length such
     * that the total length is a multiple of 512 bits."
     * As bytes: (<message length> + 1 + <zero padding length> + 4) % 64 == 0
     */
    int pad_len = 0; while ((msg_len + 1 + pad_len + 4) % 64) {
        pad_len++;
    }
    int tot_len = msg_len + 1 + pad_len + 4;

    byte chunk[64];
    const uint64_t L = msg_len * 8;
    int i = 0; while (i < tot_len) {
        int j = 0; while (j < 64) {
                 if (i  < msg_len    ) chunk[j] = msg[i];
            else if (i == msg_len    ) chunk[j] = 0x80;
            else if (i  < tot_len - 4) chunk[j] = 0x00;
            else if (i == tot_len - 4) chunk[j] = L >> 0x18;
            else if (i == tot_len - 3) chunk[j] = L >> 0x10;
            else if (i == tot_len - 2) chunk[j] = L >> 0x08;
            else if (i == tot_len - 1) chunk[j] = L >> 0x00;
            j++;
            i++;
        }
        sha256_chunk(hash, chunk);
    }

	/* Produce the final hash value (big-endian) */
    i = 0; while (i < 8) {
        digest[4 * i + 0] = hash[i] >> 0x18;
        digest[4 * i + 1] = hash[i] >> 0x10;
        digest[4 * i + 2] = hash[i] >> 0x08;
        digest[4 * i + 3] = hash[i] >> 0x00;
        i++;
    }
}

/* TESTS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void dump(const byte* bin, const int len) {
    int i = 0; while (i < len) printf("%02x", bin[i++]); puts("");
}
byte* hex2bin(const char* hex) {
    const int len = strlen(hex) / 2;
    byte* bin = (byte*)malloc(len);
    const char* pos = hex;
    int i = 0; while (i < len) {
        sscanf(pos, "%2hhx", &bin[i]);
        pos += 2;
        i++;
    }
    return bin;
}
void test(const char* want_hex, const char* gave_hex) {
    const int len = strlen(gave_hex) / 2;
    byte* gave = hex2bin(gave_hex);
    byte* want = hex2bin(want_hex);
    byte hash[32];
    sha256(hash, gave, len);
    int i = 0; while (i < 32) {
        if (want[i] != hash[i]) {
            puts("TEST FAILED");
            printf("Gave: "); dump(gave, len);
            printf("Want: "); dump(want, 32);
            printf("Hash: "); dump(hash, 32);
            exit(1);
            return;
        }
        i++;
    }
}
int main(int argc, char** argv) {
    puts("testing...");
    test("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "");
    test("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", "00");
    test("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "616263");
    test("ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c", "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e");
    test("1ebb2bdc5ce08e6e90b3ede72a8ef315e3e1bced3a3c458f69b6d7eeff9e4f3a", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    test("f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    test("f408ef6cd57f6a22a504e440722fe8aa9462ab8cf70480fd52fc06acfb44a2c3", "4dfbde451f444d2c2a6e3afe4c543fe64dfbde451f444d2c2a6e3afe4c543fe64dfbde451f444d2c2a6e3afe4c543fe64dfbde451f444d2c2a6e3afe4c543fe64dfbde451f444d2c2a6e3afe4c543fe64dfbde451f444d2c2a6e3afe4c543fe64dfbde451f444d2c2a6e3afe4c543fe64dfbde451f444d2c2a6e3afe4c543fe64dfbde451f444d2c2a6e3afe4c543fe64dfbde451f444d2c2a6e3afe4c543fe64dfbde451f444d2c2a6e3afe4c543fe64dfbde451f444d2c2a6e3afe4c543fe64dfbde451f444d2c2a6e3afe4c543fe64dfbde451f444d2c2a6e3afe4c543fe64dfbde451f444d2c2a6e3afe4c543fe600");
    puts("passed");
    return 0;
}
*/

#undef word
#undef byte
#undef ROTR

#endif
