#include <stdio.h>    
#include <stdlib.h>   
#include <string.h>
#include <sodium.h>
#include <getopt.h>

void printer(){
    printf("Options:\n");
    printf("  -o path    : Path to the output file\n");
    printf("  -a hex_key : Alice's private key (hex)\n");
    printf("  -b hex_key : Bob's private key (hex)\n");
    printf("  -c context : Context string (8 bytes, default: \"ECDH_KDF\")\n");
    printf("  -h         : Show this help message\n");

}

int generator(unsigned char *public_key, unsigned char *secret_key, const char *input_sk) {
    
    if (input_sk == NULL) {
        randombytes_buf(secret_key, crypto_kx_SECRETKEYBYTES);
    } 
    else 
    {
        const char *mod_input = input_sk;
        if (strncmp(mod_input, "0x", 2) == 0) mod_input += 2;

        if (strlen(mod_input) != crypto_kx_SECRETKEYBYTES * 2) {
            fprintf(stderr, "Error Blyat! Private key must be 64 hex characters.\n");
            return 1;
        }
        if (sodium_hex2bin(secret_key, crypto_kx_SECRETKEYBYTES, mod_input, strlen(mod_input), NULL, NULL, NULL) != 0) {
            fprintf(stderr, "Error Blyat! Invalid hex format for private key\n");
            return 1;
        }
    }
    // Α = a * G 
    if (crypto_scalarmult_base(public_key, secret_key) != 0) {
        fprintf(stderr, "Error Blayt! Failed to compute public key\n");
        return 1;
    }

    return 0;
}

int main(int argc, char *argv[]){

//1
sodium_init();

printf("\nPrivate key length: %zu\n",crypto_kx_SECRETKEYBYTES);

char *output_file = NULL;
char *s_a = NULL;
char *s_b = NULL;
const char *context = "ECDH_KDF"; 
int opt;

while ((opt = getopt(argc, argv, "o:a:b:c:h")) != -1) {
    switch (opt) {
        case 'o':
            output_file = optarg;
            break;
        case 'a':
            s_a = optarg;
            break;
        case 'b':
            s_b = optarg;
            break;
        case 'c':

        context = optarg;

        if (strlen(context) != crypto_kdf_CONTEXTBYTES) {
            fprintf(stderr, "Error: Context (-c) must be exactly 8 bytes long.\n");
            fprintf(stderr, "Examples: \"ECDH_KDF\" or \"koukou25\"\n");
            return 1;
        }
            break;
        case 'h':
            printer(); 
            return 0;
        default: 
            printer();
            return 1;
    }
}

if (output_file == NULL) {
        fprintf(stderr, "Error: Output file (-o) is required.Blyat\n");
        printer();
        return 1;
    }

//2,3
unsigned char alice_pk[crypto_kx_PUBLICKEYBYTES];
unsigned char alice_sk[crypto_kx_SECRETKEYBYTES];
unsigned char bob_pk[crypto_kx_PUBLICKEYBYTES];
unsigned char bob_sk[crypto_kx_SECRETKEYBYTES];


if (generator(alice_pk, alice_sk, s_a) != 0) 
    return 1;
if (generator(bob_pk, bob_sk, s_b) != 0) 
    return 1;

printf("Nice Blyat! Public keys have generated\n");

//4
unsigned char shared_A[crypto_kx_SESSIONKEYBYTES];
unsigned char shared_B[crypto_kx_SESSIONKEYBYTES];

if (crypto_scalarmult(shared_A, alice_sk, bob_pk) != 0) 
    return 1;
if (crypto_scalarmult(shared_B, bob_sk, alice_pk) != 0) 
    return 1;


//5
unsigned char enc_key_A[32]; 
unsigned char mac_key_A[32]; 
unsigned char enc_key_B[32];
unsigned char mac_key_B[32];

crypto_kdf_derive_from_key(enc_key_A, sizeof(enc_key_A), 1, context, shared_A);
crypto_kdf_derive_from_key(mac_key_A, sizeof(mac_key_A), 2, context, shared_A);

crypto_kdf_derive_from_key(enc_key_B, sizeof(enc_key_B), 1, context, shared_B);
crypto_kdf_derive_from_key(mac_key_B, sizeof(mac_key_B), 2, context, shared_B);
printf("Eazy Blyat! Derived keys successfully.\n");

//write to output file 
FILE *fp = fopen(output_file, "w");
if (fp == NULL) {
    fprintf(stderr, "Error Blyat! Could not open output file %s\n", output_file);
    return 1;
}


char file_buffer[crypto_kx_PUBLICKEYBYTES * 2 + 1];

sodium_bin2hex(file_buffer, sizeof(file_buffer), alice_pk, sizeof(alice_pk));
fprintf(fp, "Alice's Public Key:\n%s\n", file_buffer);

sodium_bin2hex(file_buffer, sizeof(file_buffer), bob_pk, sizeof(bob_pk));
fprintf(fp, "Bob's Public Key:\n%s\n", file_buffer);

sodium_bin2hex(file_buffer, sizeof(file_buffer), shared_A, sizeof(shared_A));
fprintf(fp, "Shared Secret (Alice):\n%s\n", file_buffer);

sodium_bin2hex(file_buffer, sizeof(file_buffer), shared_B, sizeof(shared_B));
fprintf(fp, "Shared Secret (Bob):\n%s\n", file_buffer);

if (sodium_memcmp(shared_A, shared_B, sizeof(shared_A)) == 0) {
    fprintf(fp, "Shared secrets match!\n");
} else {
    fprintf(fp, "Shared secrets DO NOT match!\n");
}

sodium_bin2hex(file_buffer, sizeof(file_buffer), enc_key_A, sizeof(enc_key_A));
fprintf(fp, "Derived Encryption Key (Alice):\n%s\n", file_buffer);

sodium_bin2hex(file_buffer, sizeof(file_buffer), enc_key_B, sizeof(enc_key_B));
fprintf(fp, "Derived Encryption Key (Bob):\n%s\n", file_buffer);

if (sodium_memcmp(enc_key_A, enc_key_B, sizeof(enc_key_A)) == 0) {
    fprintf(fp, "Encryption keys match!\n");
} else {
    fprintf(fp, "Encryption keys DO NOT match!\n");
}

sodium_bin2hex(file_buffer, sizeof(file_buffer), mac_key_A, sizeof(mac_key_A));
fprintf(fp, "Derived MAC Key (Alice):\n%s\n", file_buffer);

sodium_bin2hex(file_buffer, sizeof(file_buffer), mac_key_B, sizeof(mac_key_B));
fprintf(fp, "Derived MAC Key (Bob):\n%s\n", file_buffer);

if (sodium_memcmp(mac_key_A, mac_key_B, sizeof(mac_key_A)) == 0) {
    fprintf(fp, "MAC keys match!\n");
} else {
    fprintf(fp, "MAC keys DO NOT match!\n");
}

fclose(fp);
printf("Results written to %s\n", output_file);
printf("Open the file. Blyat!\n");

return 0;
    
}