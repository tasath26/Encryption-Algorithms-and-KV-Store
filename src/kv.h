#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>

/* openssl libraries */
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/bio.h>

extern char master_password[100];

void generate_aes_key(char* password);

void generate_aes_iv(char* password);

int file_exists(char* filename);

void set_master_password();

int check_password();

int AES_encryption(unsigned char* plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);

int AES_decryption(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);

int kv_add(FILE* fp, char* filename, char* key, char* value);

int kv_read(FILE* fp, char* filename, char* key);

int kv_range_read(FILE* fp, char* filename ,char* key1, char* key2);
