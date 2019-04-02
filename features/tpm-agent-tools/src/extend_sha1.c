/*
 * tpm_sealkey - binds an AES key using an existing TPM key
 * 
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Author: Jonathan Buhacoff <jonathan.buhacoff@intel.com>
 */

#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <openssl/sha.h>
#include "safe_lib.h"

#ifndef SHA1_LENGTH
#define SHA1_LENGTH 20
#endif

#ifndef BYTE
#define BYTE unsigned char
#endif

#ifndef UINT16
#define UINT16 unsigned short
#endif

#ifndef UINT32
#define UINT32 unsigned
#endif

/*
 * Input: hexadecimal character in the range 0..9 or A..F case-insensitive
 * Output: decimal value of input in the range 0..15 
 *         or -1 if the input was not a valid hexadecimal character
 */
int hex2int(const char c)
{
	//if( !isxdigit(c) ) { return -1; }
	switch(c) {
		case '0': return 0;
		case '1': return 1;
		case '2': return 2;
		case '3': return 3;
		case '4': return 4;
		case '5': return 5;
		case '6': return 6;
		case '7': return 7;
		case '8': return 8;
		case '9': return 9;
		case 'A': case 'a': return 10;
		case 'B': case 'b': return 11;
		case 'C': case 'c': return 12;
		case 'D': case 'd': return 13;
		case 'E': case 'e': return 14;
		case 'F': case 'f': return 15;
		default: return -1;
    }
}

/*
 * reads hex characters from the file handle until the first
 * non-hex character such as a space or until the max size of the
 * output buffer has been reached. returns the number of hex
 * characters read, or -1 if EOF was reached before any hex characters
 * were read
 */
int read_hex_from_file(FILE *in, BYTE *out, int max) {
	int count;
    	unsigned int b; // one byte buffer
	int scanerr;
	int end = 0;
	for(count=0; count<max; count++) {
		scanerr = fscanf(in, "%2x", &b);
		if( scanerr == EOF ) { end = 1; break; }
		if( scanerr != 1 ) { break; }
		out[count] = b & 0xFF;
	}
	if( end == 1 && count == 0 ) { return -1; }
	return count;
}

/*
 * reads hex characters from the character array until the first
 * non-hex character such as a space or until the max size of the
 * output buffer has been reached. returns the number of hex
 * characters read.
 */
int read_hex_from_str(const char *in, BYTE *out, int max) {
	int count;
    	unsigned int b; // one byte buffer
	int c1, c2; // integer values of next two hex digits
	for(count=0; count<max; count++) {
		c1 = hex2int( in[2*count] );
		c2 = hex2int( in[2*count+1] );
		if( c1 == -1 || c2 == -1 ) { break; }
		b = (c1*16)+c2;
		out[count] = b;
	}
	return count;
}

/*
 * extends the current sha1 value with the next value
 * NOTE: the result OVERWRITES the current value, so if
 * you want to keep it, make a copy of it before you call this
 */
int extend_sha1(BYTE *current, BYTE *next) {
	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, current, SHA1_LENGTH);
	SHA1_Update(&ctx, next, SHA1_LENGTH);
	SHA1_Final(current, &ctx);
	return 0;
}

/*
 * returns number of sha-1 digests read (including the first one)
 * the "result" argument must have at least SHA1_LENGTH bytes allocated
 */
int extend_from_file(FILE *in, BYTE *result) {
	BYTE next[SHA1_LENGTH];
	int digest_count = 0;
	for(;;) {
		int count = read_hex_from_file(in, next, SHA1_LENGTH);
		if( count == SHA1_LENGTH ) {
			// can extend with this
			if( digest_count == 0 ) {
				// the first input value is the initial result value
				memcpy_s(result, SHA1_LENGTH, next, SHA1_LENGTH); // note the declared sizes of SHA1_LENGTH and count == SHA1_LENGTH check above
			}
			else {
				extend_sha1(result, next);
			}
			digest_count++;
		}
		else if( count == -1 ) {
			// reached EOF without reading any more hex characters
			break;
		}
		else {
			// ignore any sequences that are not 20-byte hex representations
		}
	}
	return digest_count;
}

/*
 * returns number of sha-1 digests read (including the first one)
 * the input array must be terminated by a null entry (like argv)
 * the "result" argument must have at least SHA1_LENGTH bytes allocated
 */
int extend_from_args(const char **in, BYTE *result) {
	BYTE next[SHA1_LENGTH];
	int digest_count = 0;
	int i;
	for(i=0; in[i] != NULL; i++) {
		int count = read_hex_from_str(in[i], next, SHA1_LENGTH);
		if( count == SHA1_LENGTH ) {
			// can extend with this
			if( digest_count == 0 ) {
				// the first input value is the initial result value
				memcpy_s(result, SHA1_LENGTH, next, SHA1_LENGTH); // note the declared sizes of SHA1_LENGTH and count == SHA1_LENGTH check above
			}
			else {
				extend_sha1(result, next);
			}
			digest_count++;
		}
		else {
			// ignore any sequences that are not 20-byte hex representations
		}
	}
	return digest_count;
}

void print_hex(BYTE *data, int length, FILE *out) {
	int i;
	for(i=0; i<length; i++) {
		fprintf(out, "%02x", data[i]);
	}
}

/*
 * Usage: 
 * extend_sha1 {first} {second}
 * 
 * extend_sha1 {first} {second} {third} ...
 *
 * echo {first} > hexfile
 * echo {second} >> hexfile
 * echo {third} >> hexfile
 * cat hexfile | extend_sha1
 *
 * In all cases the program writes the extended hash to stdout in hex.
 *
 * Test cases:

./extend_sha1 0000000000000000000000000000000000000000 0000000000000000000000000000000000000000
# b80de5d138758541c5f05265ad144ab9fa86d1db

./extend_sha1 0000000000000000000000000000000000000000 de8990b384d71983a7646e65326a699acf463d3c
# 27b8c2054f13825c2433b28b45e20fa6c02a7ca5

./extend_sha1 0000000000000000000000000000000000000000 a70ce2d17d75e54fc5205c65a2734ab9fa86cd28 2fe3b71980d9690fee6855ac94a741ce0a3133d0
# 69ca5a62b1540100e142446daf6e5b3e34b9c4f0

echo 0000000000000000000000000000000000000000 > hashes
echo 0000000000000000000000000000000000000000 >> hashes
cat hashes | ./extend_sha1
# b80de5d138758541c5f05265ad144ab9fa86d1db

echo 0000000000000000000000000000000000000000 > hashes
echo de8990b384d71983a7646e65326a699acf463d3c >> hashes
cat hashes | ./extend_sha1
# 27b8c2054f13825c2433b28b45e20fa6c02a7ca5

echo 0000000000000000000000000000000000000000 > hashes
echo a70ce2d17d75e54fc5205c65a2734ab9fa86cd28 >> hashes
echo 2fe3b71980d9690fee6855ac94a741ce0a3133d0 >> hashes
cat hashes | ./extend_sha1
# 69ca5a62b1540100e142446daf6e5b3e34b9c4f0

 */
int
main (int argc, char **argv)
{
	BYTE		result[20];

	if( argc == 1 ) {
		// read hex inputs from stdin
		extend_from_file(stdin, result);
	}
	else {
		// read hex inputs from command line arguments
		extend_from_args((const char **)argv, result);
	}

	print_hex(result, SHA1_LENGTH, stdout);
	fprintf(stdout, "\n");

	return 0;
}
