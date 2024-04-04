#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

extern size_t length;

/* Functions for buffer manipulation */
extern int* cases;
char* create_buffer(char* filename);
char* convert_to_letters(char* text, int letters);
char* convert_to_full_buf(char* ciphertext, char* text);
void save_case_positions(char* text);
char* retreive_case_positions(char* text);

/* One time pad encryption functions */
char* one_time_pad_encr(char* plaintext, char* key);
char* one_time_pad_decr(char* ciphertext, char* key);
char* generate_key(char* plaintext);

/* Affine cipher functions */
extern char affine_mappings[];
char* affine_encr(char* plaintext);
char* affine_decr(char* ciphertext);

/* Substitution encryption functions */
char* substitution_decr(char* ciphertext);
int not_deciphered(char* plaintext);
void word_seek(char *pattern,char* plaintext); 

/* Trithemius cipher functions */
extern int grid[26][26];
void grid_init();
char* trithemius_encr(char* plaintext);
char* trithemius_decr(char* ciphertext);
int corresponding(char letter);

/* Scytale cipher functions */
extern int lines;
extern char** scytale;
void scytale_init(int rods,size_t len);
char* scytale_encr(char* plaintext);
char* scytale_decr(char* ciphertext);

/* Rail fence cipher functions */
extern int** rail;
void rail_init(int rails, size_t len);
char* rail_fence_encr(char* plaintext);
char* rail_fence_decr(char* ciphertext);

