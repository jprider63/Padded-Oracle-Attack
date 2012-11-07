attack: aes_core.o attack.o
	gcc -o attack attack.o cbc-padding-oracle.o aes_core.o; rm attack.o && ./attack challenge-ciphertext.txt challenge-plaintext.txt

test: aes_core.o attack.o cbc-decrypt.o
	gcc -o test -mdebug attack.o cbc-decrypt.o aes_core.o; rm attack.o && ./test ctext.txt ptext.txt

cbc-encrypt: aes_core.o cbc-encrypt.o
	gcc -o cbc-encrypt cbc-encrypt.o aes_core.o; rm cbc-encrypt.o

cbc-decrypt: aes_core.o cbc-decrypt.o
	gcc -o cbc-decrypt cbc-decrypt.o aes_core.o; rm cbc-decrypt.o

using_AES: aes_core.o using_AES.o
	gcc -o using_AES using_AES.o aes_core.o; rm using_AES.o

%.o: %.c
	gcc -g -c $^
