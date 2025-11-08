# Assignment 2: Cryptographic Implementations
**Authors:** Spyros Stamous, Michail Gialousis
**Student ID (AM):** 2021030090, 2021030065

---

## Overview

This project consists of two separate command-line tools written in C, fulfilling the requirements of Assignment 2.

1.  **`ecdh_tool` (Task 1):** A tool that implements the **Elliptic Curve Diffie-Hellman (ECDH)** key exchange protocol using the **libsodium** library. It demonstrates how two parties (Alice and Bob) can securely establish a shared secret over an insecure channel and then derive multiple keys from that secret using a Key Derivation Function (KDF).

2.  **`rsa_tool` (Task 2):** A tool that implements the **RSA (Rivest-Shamir-Adleman)** algorithm from scratch using the **GNU Multiple Precision Arithmetic (GMP)** library. This tool supports a full suite of RSA operations: key-pair generation, file encryption, file decryption, digital signatures, and performance analysis.

---

## Dependencies

To compile and run these tools, you will need the following libraries:
* **`libsodium`**: Used in both tools for cryptographic primitives (ECDH, SHA-256 hashing, KDF).
* **`libgmp`**: Used in the `rsa_tool` for arbitrary-precision arithmetic.

---

## Compilation

A `Makefile` is also included as required by the assignment. To compile both tools, simply run:

```bash
make all
```

## ecdh_tool (Task 1)

This tool simulates the **ECDH key exchange** using **Curve25519**.

### Features
- **Key Generation:** Creates public/private key pairs for Alice and Bob.  
  It can generate random keys or use user-provided private keys in hex format.  
- **Shared Secret:** Computes the shared secret for both Alice (`S_A = a*B`) and Bob (`S_B = b*A`) and verifies they match.  
- **Key Derivation (KDF):** Uses `libsodium`'s `crypto_kdf_derive_from_key` function to derive a **32-byte Encryption Key** and a **32-byte MAC Key** from the shared secret.  
- **Context Support:** Allows specifying a custom **8-byte context string** for the KDF.

### Usage

Generate random keys and derive:
```bash
./ecdh_tool -o ecdh_output.txt
```

Provide fixed private keys (hex):
```bash
./ecdh_tool -o ecdh_output.txt -a <alice_hex_key> -b <bob_hex_key>
```

Use a custom 8-byte context:
```bash
./ecdh_tool -o ecdh_output.txt -c "koukou25"
```

Show help:
```bash
./ecdh_tool -h
```

---

## rsa_tool (Task 2)

This tool provides a **from-scratch implementation** of the **RSA algorithm** and its applications.

### Features

#### Key Generation (`-g`)
- Generates `p` and `q` primes of `key_length/2` bits.  
- Calculates `n = p*q` and `λ(n) = (p-1)*(q-1)`.  
- Uses the standard public exponent `e = 65537`.  
- Calculates the private exponent `d` as the modular inverse of `e mod λ(n)`.  
- Saves keys to `public_XXXX.key` and `private_XXXX.key` files.

#### Encryption (`-e`)
- Encrypts a file using a public key:  
  `C = M^e mod n`  
- **Note:** This is a *textbook RSA* implementation, so the input file must be smaller than the key size.

#### Decryption (`-d`)
- Decrypts a file using a private key:  
  `M = C^d mod n`

#### Signing (`-s`)
- Calculates the **SHA-256** hash of the input file (using `libsodium`).  
- Signs the hash with the private key:  
  `S = H^d mod n`

#### Verification (`-v`)
- Calculates the **SHA-256** hash of the input file.  
- “Decrypts” the signature with the public key:  
  `H' = S^e mod n`  
- Compares the two hashes and prints **Signature is VALID** or **Signature is INVALID**.

#### Performance Analysis (`-a`)
- Measures the **time** and **peak memory usage** for encryption, decryption, signing, and verification.  
- Runs tests for **1024**, **2048**, and **4096-bit** key lengths.  
- Uses `fork()` and `getrusage()` for accurate, per-process measurements.  
- Saves results to `performance.txt`.

### Usage

Generate a 2048-bit key pair:
```bash
./rsa_tool -g 2048
```

Encrypt a file:
```bash
./rsa_tool -i plaintext.txt -o cipher.bin -k public_2048.key -e
```

Decrypt a file:
```bash
./rsa_tool -i cipher.bin -o decrypted.txt -k private_2048.key -d
```

Sign a file:
```bash
./rsa_tool -i plaintext.txt -o signature.sig -k private_2048.key -s
```

Verify a signature:
```bash
./rsa_tool -i plaintext.txt -k public_2048.key -v signature.sig
```

Run performance analysis:
```bash
./rsa_tool -a
```

Show help:
```bash
./rsa_tool -h
```
