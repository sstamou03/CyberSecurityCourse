CC=gcc
CFLAGS=-Wall -g
ECDH_LIBS= -lsodium
RSA_LIBS= -lgmp

all: ecdh rsa

ecdh: ecdh.c
	$(CC) $(CFLAGS) -o ecdh ecdh.c $(ECDH_LIBS)

rsa: rsa.c
	$(CC) $(CFLAGS) -o rsa rsa.c $(RSA_LIBS) $(ECDH_LIBS)

clean:

	rm -f ecdh rsa *.o
	
	rm -f *.key
	
	rm -f output.txt performance.txt decrypted.txt ciphertext.txt
	
	rm -f analysis_*.txt analysis_*.sig