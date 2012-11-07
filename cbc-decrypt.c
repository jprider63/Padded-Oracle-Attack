/* Takes a ciphertext in hex and its length (in blocks) as input;
   returns 0/1 depending on whether or not padding is implemented correctly

   For debugging purposes, uncomment the code that writes the entire
   decrypted result (including padding) to decrypt.tex, as well
   as code for more-informative error messages */

#include "aes.h"
#include <stdio.h>

/* The input ciphertext is assumed to have length an integer multiple
   of the blocklength.

   The code below is not robust to buffer-overflow attacks;
   exploiting these is not the purpose of this exercise */

int cbcdec(unsigned char* CText, int length){
  unsigned char MBlock[16];
  unsigned char CBlock_cur[16];
  unsigned char CBlock_prev[16];
  unsigned char Key[16];
  int i, j, tmp;
  FILE *fpOut;
  // FILE *fpKey;
  AES_KEY AESkey;

  fpOut = fopen("decrypt.txt", "a");
  // fpKey = fopen("key.txt", "r");

  Key[0] = 0x00, Key[1] = 0x00, Key[2] = 0x00, Key[3] = 0x00;
  Key[4] = 0x00, Key[5] = 0x00, Key[6] = 0x00, Key[7] = 0x00;
  Key[8] = 0x00, Key[9] = 0x00, Key[10] = 0x00, Key[11] = 0x00;
  Key[12] = 0x00, Key[13] = 0x00, Key[14] = 0x00, Key[15] = 0x00;

  // fclose(fpKey);

  AES_set_decrypt_key((const unsigned char *) Key, 128, &AESkey);

  if (length < 2) return 0;

  for (i=0; i<16; i++)
    CBlock_prev[i] = CText[i];

  j = 1;

  while (j < length) {
    for (i=0; i<16; i++)
      CBlock_cur[i] = CText[16*j+i];

    AES_decrypt((const unsigned char *) CBlock_cur, MBlock, (const AES_KEY *) &AESkey);

    for (i=0; i<16; i++) {
      MBlock[i] ^= CBlock_prev[i];
      //fprintf(fpOut, "%X", MBlock[i]/16), fprintf(fpOut, "%X", MBlock[i]%16);
      //printf( "%X", MBlock[i]/16), printf( "%X", MBlock[i]%16);
      // Note that we output the message + the padding for debugging purposes.
      // If we were implementing this for real, we would only output the message
      CBlock_prev[i] = CBlock_cur[i];
    }
    j++;
  }

	//fprintf(fpOut, "\n");
	//printf( "\n");
  fclose(fpOut);

  j = MBlock[15];
  if ((j==0) || (j>16)) {
    //printf("Error: final byte out of range\n");
    return 0;
  }
  for (i=14; i>=16-j; i--) {
    if (MBlock[i] != j) {
      //printf("Error: incorrect padding\n");
      return 0;
    }
  }

  // printf("Everything fine\n");
  return 1;

}
