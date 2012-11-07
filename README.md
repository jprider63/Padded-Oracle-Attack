Padded Oracle Attack
--------------------

This is a padded oracle attack I implemented for CMSC498L, *Cybersecurity Lab*. It is written in C and decrypts ciphertexts encrypted with AES in CBC mode. The attack relies on the ability to query the oracle function *cbcdec*, which indicates whether decrypting a given ciphertext succeeds or not.

The implementation can be found in the file *attack.c*. Run *make* to compile the project and run the attack. It should output the plaintext of *challenge-ciphertext.txt* to *challenge-plaintext.txt*. To convert the hex to ascii, run *./hex2ascii challenge-plaintext.txt challenge-ascii.txt*.

Note: The oracle function was precompiled to the object file *cbc-padding-oracle.o* so that the key was not easily recoverable. As a result, compilation might fail on certain architectures.
