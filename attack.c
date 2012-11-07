// Used hex2ascii.c as a starting point.
// James Parker

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "cbc-decrypt.h"

// Print a block.
void printBlock( unsigned char *block) {
	int i = 0;
	while ( i < 16)
		printf( "%02X", block[i++]);
	
	printf( "\n");
}

// Print the xor of 2 blocks.
void printXorBlocks( unsigned char *b1, unsigned char *b2) {
	int i = 0;
	while ( i < 16) {
		printf( "%02X", b1[i] ^ b2[i]);

		i++;
	}
	
	printf( "\n");
}

// Decrypt a byte at block[pos].
unsigned char decryptByte( unsigned char *in, int inC, int blockOffset, int pos, unsigned char *outBlock) {
	// Copy in to cipher.
	unsigned char *cipher = (unsigned char *) malloc( inC * sizeof( unsigned char));
	memcpy( cipher, in, inC * sizeof( unsigned char));

	// Set the block.
	unsigned char *block = cipher + blockOffset;

	// Set the padding for every byte after pos.
	int i = pos + 1;
	int currentPadding = 15 - pos;
	int nextPadding = 16 - pos;

	while ( i < 16) {
		unsigned char cbcd = outBlock[i] ^ block[i];
		block[i] = nextPadding ^ cbcd; // TODO: Test boundary cases, j = 0, full padding block, etc. 

		i++;
	}

	// Find the byte at the current position.
	int blockC = blockOffset / 16 + 2;
	int posHolder = block[pos];
	block[pos] = 0;
	while ( !cbcdec( cipher, blockC)) {
		if ( block[pos]++ >= 255) {
			printf( "Error: Could not find a valid padding byte.\n");
			exit( 0);
		}
	}

	free( cipher);
	return block[pos] ^ nextPadding ^ posHolder;
}

// Carry out a padded oracle attack against a ciphertext encrypted with AES in CBC mode.
main(int argc, char *argv[]){
	if (argc != 3) {
	  printf("Usage: attack <infile> <outfile>\n");
	  return;
	}

	// Initialize files and variables.
	FILE *inputF = fopen( argv[1], "r");
	FILE *outputF = fopen( argv[2], "w");

	int inC = 128;
	unsigned char *in = (unsigned char *) malloc( inC * sizeof( unsigned char));

	// Read from inputF to in.
	int i = 0;
	while ( 1) {
		// Expand size of in if necessary.
		if ( i == inC) {
			inC *= 2;
			in = (unsigned char *) realloc( in, inC * sizeof( unsigned char));
		}

		// Scan input. Break if EOF.
		if ( fscanf( inputF, "%02X", (in + i)) == EOF)
			break;

		i++;
	}
	
	// Set the number of blocks.
	int blockC = i / 16;

	// Check if the input ciphertext is valid.
	if ( !cbcdec( in, blockC)) {
		printf( "Error: Input file does not have valid ciphertext.\n");
		exit( 0);
	}

	// Copy in to tmp. Create the output out.
	unsigned char *tmp = (unsigned char *) malloc( inC * sizeof( unsigned char));
	memcpy( tmp, in, inC * sizeof( unsigned char));
	unsigned char *out = (unsigned char *) malloc( inC * sizeof( unsigned char));

	// Find the padding.
	int blockI = blockC - 1;
	int pos = (blockI - 1) * 16;

	int j = 0;
	while ( j < 16) {
		tmp[pos + j] ^= -1;

		if ( !cbcdec( tmp, blockC))
			break;
		
		j++;
	}

	// Write padding to out.
	pos = blockI * 16;
	int paddingPos = j;
	while ( j < 16)
		out[pos + j++] = 16 - paddingPos;
	
	// Decrypt rest of the plaintext.
	j =  paddingPos - 1;
	while ( blockI > 0) {
		while ( j >= 0) {
			out[blockI * 16 + j] = decryptByte( in, inC, (blockI - 1) * 16, j, out + blockI * 16);

			j--;
		}

		j = 15;
		blockI--;
	}

	// Write to outputF.
	j = 16;
	while ( j < i) {
		fprintf( outputF, "%02X", out[j]);

		j++;
	}
	printf( "\n");

	// Close files and variables.
	free( out);
	free( tmp);
	free( in);

	fclose( inputF);
	fclose( outputF);
}
