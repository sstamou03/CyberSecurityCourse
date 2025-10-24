# CyberSecurityCourse (Oi kaloi) 
**Exercise 1:** Secure Server-Client Program using OpenSSL in C
**Authors:** Spyros Stamous, Michail Gialousis

## Overview

The system consists of:
- `server.c` — a TLS server that requires valid client certificates.
- `client.c` — a legitimate client whose certificate is signed by the trusted CA.
- `rclient.c` — a rogue client using a certificate from an untrusted CA.

## Certificate Generation

### 1) Create CA private key and self-signed certificate

openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ca.key -out ca.crt \
-subj "/C=GR/ST=Crete/L=Chania/O=TechnicalUniversityofCrete/OU=ECELab/CN=RootCA"

#### Parameters:

-x509 → Creates a self-signed CA certificate

-nodes → Do not encrypt the private key

-days 365 → Valid for 1 year

-newkey rsa:2048 → Generates a 2048-bit RSA key

-subj → Provides subject info (C, ST, L, O, OU, CN)

### 2) Create Server Key and CSR

openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
-subj "/C=GR/ST=Crete/L=Chania/O=TechnicalUniversityofCrete/OU=ECELab/CN=localhost"​
### 3) Sign Server Certificate with Legitimate CA

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256

#### Parameters:

-req → Input is a certificate signing request

-CA / -CAkey → CA certificate and private key

-CAcreateserial → Creates a serial number file

-sha256 → Signs using SHA-256
### 4) Create Client Key and CSR

openssl req -new -newkey rsa:2048 -nodes -keyout client.key -out client.csr \
-subj "/C=GR/ST=Crete/L=Chania/O=TechnicalUniversityofCrete/OU=ECELab/CN=client"​
### 5) Sign Client Certificate with Legitimate CA

openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 -sha256
### 6) Create Rogue CA

openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout rogue_ca.key -out rogue_ca.crt -subj "/C=GR/ST=Crete/L=Heraklion/O=CSD/OU=ITELab/CN=RogueCA"
### 7) Create Rogue Client Key and CSR

openssl req -new -newkey rsa:2048 -nodes -keyout rogue_client.key -out rogue_client.csr -subj "/C=GR/ST=Crete/L=Chania/O=CSD/OU=ITELab/CN=rogue_client"
### 8) Sign Rogue Client Certificate with Rogue CA

openssl x509 -req -in rogue_client.csr -CA rogue_ca.crt -CAkey rogue_ca.key -CAcreateserial -out rogue_client.crt -days 365 -sha256

## Q&A

### 1.​ First run the server. Example: ./server 8082
#### a.​ What is the number 8082?
      Is the port where the server listens. 
#### b.​ Can you run it on number 80, 443, 124? How can you achieve it?
      Ports below 1024 are reserved. We can bind the reserved ports if we are the root user.

### 2.​ Then run the client. Example: ./client 127.0.0.1 8082
#### a.​ What is 127.0.0.1?
      Is the localhost, the IP address that refers to our own computer.
#### b.​ What is 8082?
      This is the port that the client tries to connect to.
