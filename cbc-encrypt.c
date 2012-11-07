/*
   Reads plaintext in ascii (from msg.txt) and outputs ciphertext in hex (to ctext.txt)

   Key is provided in hex (in key.txt)

   Assumes plaintext has length an integer number of bytes,
   with padding implemented as described in class
*/

#include "aes.h"
#include <stdio.h>

main(){
  unsigned char MBlock[16];
  unsigned char CBlock_prev[16];
  unsigned char CBlock_cur[16];
  unsigned char Key[16];
  int i, j, tmp;
  FILE *fpIn;
  FILE *fpOut;
  FILE *fpKey;
  AES_KEY AESkey;

  fpIn = fopen("msg.txt", "r");
  fpOut = fopen("ctext.txt", "w");
  fpKey = fopen("key.txt", "r");

  for (i=0; i<=15; i++) {
  fscanf(fpKey, "%2X", &tmp);
  Key[i] = tmp;
//printf( "%02X", tmp);
  }

  fclose(fpKey);

  AES_set_encrypt_key((const unsigned char *) Key, 128, &AESkey);

  for (i=0; i<16; i++)
    CBlock_prev[i] = i;

  for (i=0; i<16; i++) {
    fprintf(fpOut, "%X", CBlock_prev[i]/16), fprintf(fpOut, "%X", CBlock_prev[i]%16);
  }

  while (1) {
    for (i=0; i<16; i++) {
      if (fscanf(fpIn, "%c", &MBlock[i])==EOF) break;
printf( "%02X", MBlock[i]);
      MBlock[i] ^= CBlock_prev[i];
    }

    if (i==0) break;

    if (i < 16) {
      for (j=i; j<16; j++) {
	MBlock[j] = 16-i;
	MBlock[j] ^= CBlock_prev[j];
      }
    }

    AES_encrypt((const unsigned char *) MBlock, CBlock_cur, (const AES_KEY *) &AESkey);

    for (j=0; j<16; j++) {
      fprintf(fpOut, "%X", CBlock_cur[j]/16), fprintf(fpOut, "%X", CBlock_cur[j]%16);
      CBlock_prev[j] = CBlock_cur[j];
    }

    if (i<16) break;
  }

  if (i==0) {
    for (j=0; j<16; j++) {
      MBlock[j] = 16;
      MBlock[j] ^= CBlock_prev[j];
    }

    AES_encrypt((const unsigned char *) MBlock, CBlock_cur, (const AES_KEY *) &AESkey);

    for (j=0; j<16; j++) {
      fprintf(fpOut, "%X", CBlock_cur[j]/16), fprintf(fpOut, "%X", CBlock_cur[j]%16);
      CBlock_prev[j] = CBlock_cur[j];
    }
  }

  fclose(fpOut), fclose(fpIn);
}
