#include <stdio.h>    
#include <stdlib.h>   
#include <string.h>
#include <sodium.h>
#include <getopt.h>
#include <sodium.h> 
#include <gmp.h>
#include <time.h>
#include <sys/time.h>   // For getrusage
#include <sys/resource.h> // For getrusage

void printer(){
    printf("Options:\n");
    printf("  -i path     Path to the input file\n");
    printf("  -o path     Path to the output file\n");
    printf("  -k path     Path to the key file\n");
    printf("  -g length   Perform RSA key-pair generation given a key length \"length\"\n");
    printf("  -d          Decrypt input and store results to output\n");
    printf("  -e          Encrypt input and store results to output\n");
    printf("  -s          Sign input file and store signature to output\n");
    printf("  -v path     Verify signature (path to signature file) against input file\n");
    printf("  -a          Performance analysis with three key lengths (1024, 2048, 4096)\n");
    printf("  -h          This help message\n");

}

int key_generator(char *key_length) {

    int key_len_int = atoi(key_length);
    if (key_len_int != 1024 && key_len_int != 2048 && key_len_int != 4096) {
        fprintf(stderr, "Error Blyat! Key length must be 1024, 2048, or 4096.\n");
        return 1;
    }
 
    // GMP init
    mpz_t p, q, n, lambda, e, d, p_minus_1, q_minus_1, gcd;
    mpz_inits(p, q, n, lambda, e, d, p_minus_1, q_minus_1, gcd, NULL);

    gmp_randstate_t rstate;
    gmp_randinit_default(rstate);
    gmp_randseed_ui(rstate, time(NULL));

    // (1,2) Find q and p
    do {
        mpz_urandomb(p, rstate, key_len_int/2);   
        mpz_nextprime(p, p);                
    } while (mpz_sizeinbase(p, 2) != key_len_int/2); 

    do {
        mpz_urandomb(q, rstate, key_len_int/2);
        mpz_nextprime(q, q);
    } while (mpz_sizeinbase(q, 2) != key_len_int/2 || mpz_cmp(p, q) == 0);

    // (3) Calculate n 
    mpz_mul(n, p, q);

    // (4) Calculate lambda
    mpz_sub_ui(p_minus_1, p, 1);
    mpz_sub_ui(q_minus_1, q, 1);
    mpz_mul(lambda, p_minus_1, q_minus_1);

    // (5) Find e 
    mpz_set_ui(e, 65537); // most common chosen value for e 
    mpz_gcd(gcd, e, lambda);
    if (mpz_cmp_ui(gcd, 1) != 0) {
        fprintf(stderr, "Error Blyat! gcd(e, lambda) is not 1.\n");
        mpz_clears(p, q, n, lambda, e, d, p_minus_1, q_minus_1, gcd, NULL);
        gmp_randclear(rstate);
        return 1;
    }

    // (6) Find d 
    if (mpz_invert(d, e, lambda) == 0) {
        fprintf(stderr, "Error Blyat! Modular inverse could not be computed.\n");
        mpz_clears(p, q, n, lambda, e, d, p_minus_1, q_minus_1, gcd, NULL);
        gmp_randclear(rstate);
        return 1;
    }

    // (7, 8) Write public and private keys to keys_file 
    FILE *public_file, *private_file;
    char public_filename[50];
    char private_filename[50];

    sprintf(public_filename, "public_%d.key", key_len_int);
    sprintf(private_filename, "private_%d.key", key_len_int);

    public_file = fopen(public_filename, "w");
    if (public_file == NULL) {
        fprintf(stderr, "Error Blyat! Could not open public key file for writing.\n");
        return 1;
    }

    gmp_fprintf(public_file, "%Zd\n", n); 
    gmp_fprintf(public_file, "%Zd\n", e);
    fclose(public_file);
    
    private_file = fopen(private_filename, "w");
    if (private_file == NULL) {
        fprintf(stderr, "Error Blyat! Could not open private key file for writing.\n");
        return 1;
    }
    gmp_fprintf(private_file, "%Zd\n", n);
    gmp_fprintf(private_file, "%Zd\n", d);
    fclose(private_file);

    mpz_clears(p, q, n, lambda, e, d, p_minus_1, q_minus_1, gcd, NULL);
    gmp_randclear(rstate);

    printf("NIIIICE BLYAT! Keys generated successfully!");
    
    return 0;
  
}

int data_encrypt(char *input_file, char* output_file, char* keys_file){
    
    // check for correct arguments
    if (input_file == NULL || output_file == NULL || keys_file == NULL) {
        fprintf(stderr, "Error Blyat! Encryption requires -i, -o, and -k arguments.\n");
        return 1;
    }

    // init gmp
    mpz_t M, C, n, e;
    mpz_inits(M, C, n, e, NULL);

    // read public key
    FILE *public_key_file = fopen(keys_file, "r");
    if (public_key_file == NULL) {
        fprintf(stderr, "Error Blyat! Could not open public key file: %s\n", keys_file);
        mpz_clears(M, C, n, e, NULL);
        return 1;
    }
    gmp_fscanf(public_key_file, "%Zd\n%Zd", n, e); 
    fclose(public_key_file);

    // read input file
    FILE *in_file = fopen(input_file, "rb"); // "rb" = Read Binary
    if (in_file == NULL) {
        fprintf(stderr, "Error: Could not open input file: %s\n", input_file);
        mpz_clears(M, C, n, e, NULL);
        return 1;
    }

    // Check if input file is smaller than RSA key size
    fseek(in_file, 0, SEEK_END);
    long file_size = ftell(in_file);
    fseek(in_file, 0, SEEK_SET);

    
    size_t key_bytes = (mpz_sizeinbase(n, 2) + 7) / 8;

    
    if (file_size >= key_bytes) {
        fprintf(stderr, "Error Blyat! Input file (%ld bytes) is larger than key size (%zu bytes).\n",
                file_size, key_bytes);
        fprintf(stderr, "This is a simple version and cannot encrypt files larger than the key. :(\n");
        fclose(in_file);
        mpz_clears(M, C, n, e, NULL);
        return 1;
    }

    // read input file
    unsigned char *buffer = malloc(file_size);
    if (buffer == NULL) {
        fprintf(stderr, "Error Blyat! Failed to allocate memory for buffer.\n");
        fclose(in_file);
        mpz_clears(M, C, n, e, NULL);
        return 1;
    }
    
    if (fread(buffer, 1, file_size, in_file) != file_size) {
        fprintf(stderr, "Error Blyat! Failed to read input file.\n");
        fclose(in_file);
        free(buffer);
        mpz_clears(M, C, n, e, NULL);
        return 1;
    }
    fclose(in_file);

    // create M (the large integer of the file) 
    mpz_import(M, file_size, 1, 1, 0, 0, buffer);

    // RSA encryption; create C
    // C = M^e mod n
    mpz_powm(C, M, e, n);

    // write cipher text to output file
    FILE *out_file = fopen(output_file, "w");
    if (out_file == NULL) {
        fprintf(stderr, "Error Blyat! Could not open output file: %s\n", output_file);
        free(buffer);
        mpz_clears(M, C, n, e, NULL);
        return 1;
    }
    
    gmp_fprintf(out_file, "%Zd\n", C); 
    fclose(out_file);

    // clean
    free(buffer);
    mpz_clears(M, C, n, e, NULL);

    printf("YEEEES BLYAT! Get ciphered!");
    return 0;

}

int data_decrypt(char *input_file, char* output_file, char* keys_file){
    // check for correct arguments
    if (input_file == NULL || output_file == NULL || keys_file == NULL) {
        fprintf(stderr, "Error Blyat! Decryption requires -i, -o, and -k arguments.\n");
        return 1;
    }

    //gmp init 
    mpz_t C, M, n, d;
    mpz_inits(C, M, n, d, NULL);

    //read private key
    FILE *key_file = fopen(keys_file, "r");
    if (key_file == NULL) {
        fprintf(stderr, "Error Blyat! Could not open private key file: %s\n", keys_file);
        mpz_clears(C, M, n, d, NULL);
        return 1;
    }

    // n
    if (gmp_fscanf(key_file, "%Zd", n) != 1) {
        fprintf(stderr, "Error Blyat! Could not read 'n' from key file.\n");
        fclose(key_file);
        mpz_clears(C, M, n, d, NULL);
        return 1;
    }
    //read k
    if (gmp_fscanf(key_file, "%Zd", d) != 1) {
        fprintf(stderr, "Error Blyat! Could not read 'd' from key file.\n");
        fclose(key_file);
        mpz_clears(C, M, n, d, NULL);
        return 1;
    }
    fclose(key_file);

    //read input -i
    FILE *in_file = fopen(input_file, "r");
    if (in_file == NULL) {
        fprintf(stderr, "Error Blyat! Could not open input file: %s\n", input_file);
        mpz_clears(C, M, n, d, NULL);
        return 1;
    }

    //find c -> (Ciphertex)
    if (gmp_fscanf(in_file, "%Zd", C) != 1) {
        fprintf(stderr, "Error Blyat! Could not read ciphertext 'C' from input file.\n");
        fclose(in_file);
        mpz_clears(C, M, n, d, NULL);
        return 1;
    }
    fclose(in_file);

    // RSA encryption;make M
    //M = C^d mod n
    mpz_powm(M, C, d, n);

    //make M -> text; save it 
    FILE *out_file = fopen(output_file, "wb"); 
    if (out_file == NULL) {
        fprintf(stderr, "Error Blyat! Could not open output file: %s\n", output_file);
        mpz_clears(C, M, n, d, NULL);
        return 1;
    }

    // put M in a buffer 
    size_t buffer_size;
    unsigned char *buffer = mpz_export(NULL, &buffer_size, 1, 1, 0, 0, M);

    // write the buffer to the output file
    if (fwrite(buffer, 1, buffer_size, out_file) != buffer_size) {
            fprintf(stderr, "Error Blyat! Failed to write decrypted data to output file.\n");
        }

    fclose(out_file);
    free(buffer);
    mpz_clears(C, M, n, d, NULL);

    printf("Ha Blyat! Get decrypted ");
    return 0;

}

int sign(char *input_file, char *output_file, char *keys_file){
    
    // check for correct arguments
    if (input_file == NULL || output_file == NULL || keys_file == NULL) {
        fprintf(stderr, "Error Blyat! Signing requires -i, -o, and -k arguments.\n");
        return 1;
    }

    // (1) read plaintext from an input file 
    FILE *in_file = fopen(input_file, "rb"); // Read Binary
    if (in_file == NULL) {
        fprintf(stderr, "Error Blyat! Could not open input file: %s\n", input_file);
        return 1;
    }

    fseek(in_file, 0, SEEK_END);
    long file_size = ftell(in_file);
    fseek(in_file, 0, SEEK_SET);

    unsigned char *buffer = malloc(file_size);
    if (buffer == NULL) {
        fprintf(stderr, "Error Blyat! Failed to allocate memory for buffer.\n");
        fclose(in_file);
        return 1;
    }

    if (fread(buffer, 1, file_size, in_file) != file_size) {
        fprintf(stderr, "Error Blyat! Failed to read input file.\n");
        fclose(in_file);
        free(buffer);
        return 1;
    }
    fclose(in_file);

    // (2) compute the SHA-256 hash of the plaintext
    unsigned char hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash, buffer, file_size);
    free(buffer);


    // (3) sign the hash using the private key (this is RSA signing: signature = hash^d mod n)
    mpz_t H, S, n, d; 
    mpz_inits(H, S, n, d, NULL);

    // read private key (n and d)
    FILE *k_file = fopen(keys_file, "r");
    if (k_file == NULL) {
        fprintf(stderr, "Error Blyat! Could not open private key file: %s\n", keys_file);
        mpz_clears(H, S, n, d, NULL);
        return 1;
    }

    if (gmp_fscanf(k_file, "%Zd", n) != 1) {
        fprintf(stderr, "Error Blyat! Could not read 'n' from key file.\n");
        fclose(k_file);
        mpz_clears(H, S, n, d, NULL);
        return 1;
    }
    if (gmp_fscanf(k_file, "%Zd", d) != 1) {
        fprintf(stderr, "Error Blyat! Could not read 'd' from key file.\n");
        fclose(k_file);
        mpz_clears(H, S, n, d, NULL);
        return 1;
    }
    fclose(k_file);

    // Import the hash into an mpz_t
    mpz_import(H, crypto_hash_sha256_BYTES, 1, 1, 0, 0, hash);

    // Sign the hash (S = H^d mod n)
    mpz_powm(S, H, d, n);

    // (4) store the signature in an output file
    FILE *out_file = fopen(output_file, "w");
    if (out_file == NULL) {
        fprintf(stderr, "Error Blyat! Could not open output file: %s\n", output_file);
        mpz_clears(H, S, n, d, NULL);
        return 1;
    }

    gmp_fprintf(out_file, "%Zd\n", S);
    fclose(out_file);

    // clean
    mpz_clears(H, S, n, d, NULL);
    
    printf("DA BLYAT! File freaking signed.\n");
    return 0;
}

int verify(char *input_file, char *signature_file, char *keys_file){

    // check for correct arguments
    if (input_file == NULL || signature_file == NULL || keys_file == NULL) {
        fprintf(stderr, "Error Blyat! Verification requires -i, -v, and -k arguments.\n");
        return 1;
    }

    // (1) read plaintext from an input file 
    FILE *in_file = fopen(input_file, "rb"); 
    if (in_file == NULL) {
        fprintf(stderr, "Error Blyat! Could not open input file: %s\n", input_file);
        return 1;
    }

    fseek(in_file, 0, SEEK_END);
    long file_size = ftell(in_file);
    fseek(in_file, 0, SEEK_SET);

    unsigned char *buffer = malloc(file_size);
    if (buffer == NULL) {
        fprintf(stderr, "Error Blyat! Failed to allocate memory for buffer.\n");
        fclose(in_file);
        return 1;
    }

    if (fread(buffer, 1, file_size, in_file) != file_size) {
        fprintf(stderr, "Error Blyat! Failed to read input file.\n");
        fclose(in_file);
        free(buffer);
        return 1;
    }
    fclose(in_file);

    // (2) compute the SHA-256 hash of the plaintext 
    unsigned char original_hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(original_hash, buffer, file_size);
    free(buffer); 

    // gmp init
    mpz_t S, n, e, original_hash_mpz, computed_hash_mpz;
    mpz_inits(S, n, e, original_hash_mpz, computed_hash_mpz, NULL);

    // read public key (n and e) 
    FILE *key_file = fopen(keys_file, "r");
    if (key_file == NULL) {
        fprintf(stderr, "Error Blyat! Could not open public key file: %s\n", keys_file);
        mpz_clears(S, n, e, original_hash_mpz, computed_hash_mpz, NULL);
        return 1;
    }
    if (gmp_fscanf(key_file, "%Zd\n%Zd", n, e) != 2) {
        fprintf(stderr, "Error Blyat! Could not read 'n' and 'e' from key file.\n");
        fclose(key_file);
        mpz_clears(S, n, e, original_hash_mpz, computed_hash_mpz, NULL);
        return 1;
    }
    fclose(key_file);

    // read signature from signature file 
    FILE *sig_file = fopen(signature_file, "r");
    if (sig_file == NULL) {
        fprintf(stderr, "Error Blyat! Could not open signature file: %s\n", signature_file);
        mpz_clears(S, n, e, original_hash_mpz, computed_hash_mpz, NULL);
        return 1;
    }
    if (gmp_fscanf(sig_file, "%Zd", S) != 1) {
        fprintf(stderr, "Error Blyat! Could not read signature 'S' from file.\n");
        fclose(sig_file);
        mpz_clears(S, n, e, original_hash_mpz, computed_hash_mpz, NULL);
        return 1;
    }
    fclose(sig_file);

    // (3) Verify the signature (compute: hash' = signature^e mod n) 
    mpz_powm(computed_hash_mpz, S, e, n);

    // (4, 5) compare hash' with the original hash and output
    mpz_import(original_hash_mpz, crypto_hash_sha256_BYTES, 1, 1, 0, 0, original_hash);

    if (mpz_cmp(original_hash_mpz, computed_hash_mpz) == 0) {
        printf("Signature is VALID\n");
    } else {
        printf("Signature is INVALID\n");
    }

    // clean up
    mpz_clears(S, n, e, original_hash_mpz, computed_hash_mpz, NULL);
    return 0;
}

int performance_analysis(char *output_file){

    if (output_file == NULL) {
        fprintf(stderr, "Error Blyat! Performance analysis requires an output file (-o).\n");
        return 1;
    }

    FILE *out_f = fopen(output_file, "w");
    if (out_f == NULL) {
        fprintf(stderr, "Error Blyat! Could not open output file: %s\n", output_file);
        return 1;
    }

    printf("Running performance analysis blyaaat... This may take a moment.\n");

    int key_lengths[] = {1024, 2048, 4096};
    int num_lengths = sizeof(key_lengths) / sizeof(key_lengths[0]);
    char *plaintext_file = "analysis_plaintext.txt";
    char *ciphertext_file = "analysis_cipher.txt";
    char *decrypted_file = "analysis_decrypted.txt";
    char *signature_file = "analysis_sig.sig";

    // create a dummy plaintext file to operate on
    FILE *pt_file = fopen(plaintext_file, "w");
    if (pt_file == NULL) {
        fprintf(stderr, "Error Blyat! Could not create temp plaintext file.\n");
        fclose(out_f);
        return 1;
    }
    fprintf(pt_file, "test blyat! test!");
    fclose(pt_file);

    struct rusage usage; // For memory usage

    for (int i = 0; i < num_lengths; i++) {
        int key_len = key_lengths[i];
        char key_len_str[5];
        sprintf(key_len_str, "%d", key_len);

        char pub_key_file[50];
        char priv_key_file[50];
        sprintf(pub_key_file, "public_%d.key", key_len);
        sprintf(priv_key_file, "private_%d.key", key_len);

        fprintf(out_f, "Key Length: %d bits\n", key_len);

        // (1) Generate Keys 
        key_generator(key_len_str);

        clock_t start, end;
        double time_taken;
        long peak_mem; // For storing peak memory usage

        // (2) Measure Encryption
        start = clock();
        data_encrypt(plaintext_file, ciphertext_file, pub_key_file);
        end = clock();
        time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;

        getrusage(RUSAGE_SELF, &usage);
        peak_mem = usage.ru_maxrss; // Peak RSS in KB on Linux

        fprintf(out_f, "Encryption Time: %.2fs\n", time_taken);

        fprintf(out_f, "Peak Memory Usage (Encryption): %ld KB\n", peak_mem);

        // (3) Measure Decryption
        start = clock();
        data_decrypt(ciphertext_file, decrypted_file, priv_key_file);
        end = clock();
        time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;

        getrusage(RUSAGE_SELF, &usage);
        peak_mem = usage.ru_maxrss;

        fprintf(out_f, "Decryption Time: %.2fs\n", time_taken);

        fprintf(out_f, "Peak Memory Usage (Decryption): %ld KB\n", peak_mem);

        // (4) Measure Signing
        start = clock();
        sign(plaintext_file, signature_file, priv_key_file);
        end = clock();
        time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;

        getrusage(RUSAGE_SELF, &usage);
        peak_mem = usage.ru_maxrss;

        fprintf(out_f, "Signing Time: %.2fs\n", time_taken);

        fprintf(out_f, "Peak Memory Usage (Signing): %ld KB\n", peak_mem);

        // (5) Measure Verification
        start = clock();
        verify(plaintext_file, signature_file, pub_key_file);
        end = clock();
        time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;

        getrusage(RUSAGE_SELF, &usage);
        peak_mem = usage.ru_maxrss;

        fprintf(out_f, "Verification Time: %.2fs\n", time_taken);

        fprintf(out_f, "Peak Memory Usage (Verification): %ld KB\n\n", peak_mem);

        // Note on Memory Usage:
        // Measuring peak memory usage per function call in standard C is non-trivial
        // and platform-dependent (e.g., using getrusage() on POSIX).
        // This is often measured using external tools like /usr/bin/time -v or Valgrind.
        // fprintf(out_f, "Peak Memory Usage (Encryption): Not Measured\n");
        // fprintf(out_f, "Peak Memory Usage (Decryption): Not Measured\n");
        // fprintf(out_f, "Peak Memory Usage (Signing): Not Measured\n");
        // fprintf(out_f, "Peak Memory Usage (Verification): Not Measured\n\n");

        // clean up temporary files for this iteration
        remove(pub_key_file);
        remove(priv_key_file);
        remove(ciphertext_file);
        remove(decrypted_file);
        remove(signature_file);
    }

    // clean up the main plaintext file
    remove(plaintext_file);
    fclose(out_f);

    printf("Analysis done BLYAAAAT! Results saved to %s\n", output_file);
    return 0;
}

int main(int argc, char *argv[]){

sodium_init();

char *input_file = NULL;
char *output_file = NULL;
char *keys_file = NULL;
char *signature_file = NULL; 
char *key_length = NULL; 
    


int g_opt=0, e_opt=0, d_opt=0, s_opt=0, v_opt=0, a_opt=0;
int opt;

while ((opt = getopt(argc, argv, "i:o:k:g:desv:a:h")) != -1) {
     switch (opt) {
            case 'i':
                input_file = optarg;
                break;
            case 'o':
                output_file = optarg;
                break;
            case 'k':
                keys_file = optarg;
                break;
            case 'g':
                g_opt = 1;
                key_length = optarg;
                break;
            case 'd':
                d_opt = 1;
                break;
            case 'e':
                e_opt = 1;
                break;
            case 's': 
                s_opt = 1;
                break;
            case 'v':
                v_opt = 1;
                signature_file = optarg;
                break;
            case 'a':
                a_opt = 1;
                output_file = optarg;
                break;
            case 'h':
                printer();
                return 0;
            default: // Άγνωστη επιλογή
                printer();
                return 1;
        }
    }

    printf("Good choice Blyat!");

    if (g_opt) {
        printf("Mode: Key Generation (Length: %s)\n", key_length);
        key_generator(key_length);
    } 
    else if (e_opt) {
        printf("Mode: Encrypt\n");
        data_encrypt(input_file, output_file, keys_file);
    } 
    else if (d_opt) {
        printf("Mode: Decrypt\n");
        data_decrypt(input_file, output_file, keys_file);
    }
    else if (s_opt) {
        printf("Mode: Sign\n");
        sign(input_file, output_file, keys_file);
    }
    else if (v_opt) {
        printf("Mode: Verify\n");
        verify(input_file, signature_file, keys_file);
    }
    else if (a_opt) {
        printf("Mode: Performance Analysis\n");
        performance_analysis(output_file);
    }
    else {
        fprintf(stderr, "Error Blyat! No mode selected.\n");
        printer();
        return 1;
    }
    
    return 0;
}