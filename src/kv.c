#include "kv.h"

static unsigned char aes_key[32];
static unsigned char aes_iv[16];

char master_password[100];
unsigned char password_hash[SHA256_DIGEST_LENGTH];

int kv_add(FILE* fp,char* filename, char* key, char* value){
  fp = fopen(filename, "a");
  
  unsigned char* key_plaintext = (unsigned char*)key;
  unsigned char key_ciphertext[128];

  unsigned char* value_plaintext = (unsigned char*)value;
  unsigned char value_ciphertext[128];
 
  AES_encryption(key_plaintext, strlen((char*)key_plaintext),aes_key , aes_iv, key_ciphertext);
  AES_encryption(value_plaintext, strlen((char*)value_plaintext), aes_key, aes_iv, value_ciphertext);
 
  fprintf(fp, "%s,%s\n", key_ciphertext,value_ciphertext);

  fclose(fp);

  printf("Added Successfully\n");
  return 0;
}

int kv_read(FILE* fp,char* filename, char* key){
  fp = fopen(filename, "r");
 
  size_t lenn = 0;
  int found = 1;
  char* tmp;
  unsigned char plaintext[128];
  char buffer[1024];
  unsigned long curr_key;
  unsigned long curr_val;
 
  int row = 0;
  int column = 0;
 
  while (fgets(buffer,1024, fp)) {
    column = 0;
    row++;
 
    if (row == 1){
      continue;
    } 
       
    char* value = strtok(buffer, ",");
    while (value) {
                
      if (column == 0) {
        AES_decryption((unsigned char*)value, strlen(value), aes_key, aes_iv, plaintext);
        lenn = 0;
                    
        for(int i = 0; plaintext[i] >= '0' && plaintext[i] <= '9'; i++){
          lenn++;
        }
        plaintext[lenn] = '\0';
        curr_key = atoi((char*)plaintext);
                  
      }


      if(atoi(key) == curr_key){
          
        if (column == 1) {
          AES_decryption((unsigned char*)value, strlen(value), aes_key, aes_iv, plaintext);
          lenn = 0;

          
          for(int i = 0; plaintext[i] >= '0' && plaintext[i] <= '9'; i++){
            lenn++;
          }

          plaintext[lenn] = '\0';
          curr_val = atoi((char*)plaintext);
              
          printf("Key = %lu, Value = %lu\n",curr_key,curr_val);
          return 0;

          }

        }

          value = strtok(NULL, ",");
          column++;

    } 
  }
 


  fclose(fp);
  return 0;
}

int kv_range_read(FILE *fp,char* filename, char* key1, char* key2){
  fp = fopen(filename, "r");

  int read[5000] = {-1};
  int k = 0;
  size_t lenn = 0;
  int cont = 0;
  char* tmp;
  unsigned char plaintext[128];
  char buffer[1024];
  unsigned long curr_key;
  unsigned long curr_val;

  int row = 0;
  int column = 0;
 
  while (fgets(buffer,1024, fp)) {
    column = 0;
    row++;
 
    if (row == 1){
      continue;
    } 
       
    char* value = strtok(buffer, ",");
    while (value) {
                
      
      if (column == 0) {
        cont = 0;
        AES_decryption((unsigned char*)value, strlen(value), aes_key, aes_iv, plaintext);
        lenn = 0;
                    
        for(int i = 0; plaintext[i] >= '0' && plaintext[i] <= '9'; i++){
          lenn++;
        }
        plaintext[lenn] = '\0';
        curr_key = atoi((char*)plaintext);
        
        for(int i = 0; i < k; i++){
          if(curr_key == read[i]){
            cont = 1;
            break;
          }
        }
        
        read[k] = curr_key;
        k++;
                          
      }


      if(atoi(key1) <= curr_key && atoi(key2) >= curr_key && cont == 0){
          
        if (column == 1) {
          AES_decryption((unsigned char*)value, strlen(value), aes_key, aes_iv, plaintext);
          lenn = 0;

          
          for(int i = 0; plaintext[i] >= '0' && plaintext[i] <= '9'; i++){
            lenn++;
          }

          plaintext[lenn] = '\0';
          curr_val = atoi((char*)plaintext);
              
          printf("Key = %lu, Value = %lu\n",curr_key,curr_val);
        

          }

        }

          value = strtok(NULL, ",");
          column++;

    } 
  }
 


  fclose(fp);
  return 0;
}

void generate_aes_key(char *password){

  int k = 0;
  for(int i = 0 ; i < 32; i++){
    aes_key[i] = password[k];
    if(k == strlen(password) - 1){
      k = 0;
    }
  }
}

void generate_aes_iv(char* password){
  
  int k = 0;
  for(int i = 0 ; i < 16; i++){
    aes_iv[i] = password[k];
    if(k == strlen(password) - 1){
      k = 0;
    }
  }

}


int file_exists(char* filename){
  if(access(filename, F_OK) != -1){ 
    return 1;
  }
  
  FILE *fp = fopen(filename, "w");
  fprintf(fp, "key,Value\n");
  fclose(fp);

  return 0;
}


int AES_encryption(unsigned char* plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext){

  int len, ciphertext_len;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
  EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
  
  ciphertext_len = len;

  EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
  EVP_CIPHER_CTX_free(ctx);

  ciphertext_len += len;  
  return ciphertext_len;

}


int AES_decryption(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext){

 
  int len, plaintext_len;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
  EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
  plaintext_len = len;
  EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

  EVP_CIPHER_CTX_free(ctx);
  
  plaintext_len += len;
  return plaintext_len;

}



void set_master_password(){
  
  printf("Enter new password: ");
  fgets(master_password, 100, stdin);
  master_password[strcspn(master_password,"\n")] = '\0';

  const EVP_MD *md = EVP_sha256();
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();

  EVP_DigestInit_ex(ctx,md,NULL);
  EVP_DigestUpdate(ctx, master_password, strlen(master_password));
  EVP_DigestFinal_ex(ctx, password_hash, NULL);
  EVP_MD_CTX_free(ctx);

  FILE* pfd = fopen(".pass","w");
  fwrite(password_hash, 1, SHA256_DIGEST_LENGTH, pfd);

  generate_aes_key(master_password);
  generate_aes_iv(master_password);

  fclose(pfd);

}

int check_password(){

  unsigned char tmp_hash[SHA256_DIGEST_LENGTH];

  printf("Enter your password: ");
  FILE* pfd = fopen(".pass","r");
  fread(password_hash, 1, SHA256_DIGEST_LENGTH, pfd);
  
  fgets(master_password, 100, stdin);
  master_password[strcspn(master_password, "\n")] = '\0';

  const EVP_MD *md = EVP_sha256();
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();

  EVP_DigestInit_ex(ctx,md,NULL);
  EVP_DigestUpdate(ctx, master_password, strlen(master_password));
  EVP_DigestFinal_ex(ctx, tmp_hash, NULL);
  EVP_MD_CTX_free(ctx); 

  for(int i = 0; i < SHA256_DIGEST_LENGTH; i++){
    if(tmp_hash[i] != password_hash[i]){
      return -1;
    }
  }

  generate_aes_key(master_password);
  generate_aes_iv(master_password);

  return 1;
  
}

int main(int argc, char** argv){


 
  int tries = 3;
  FILE *fp;
  int mode = 0;
  char* key; 
  char* val; 
  char* key2;

  if(argc > 6 || argc < 5){
    printf("Argument Error\n");
    exit(1);
  }

  if(strcmp(argv[1], "add") == 0){
    if(strcmp(argv[2],"-f") == 0){
      if(file_exists(argv[3])){

        while(tries != 0 && check_password() == -1){
          printf("Invalid password\n");
          tries--;
        }

        if(tries == 0){
          printf("Exceeded number of tries, Please try again later\n");
          exit(1);
        }

        printf("Access granted\n");
      }else{
        set_master_password();
      }
     mode = 1;
    }
   
    key = argv[4];
    val = argv[5];

  }else if(strcmp(argv[1], "read") == 0){
    if(strcmp(argv[2],"-f") == 0){
     if(file_exists(argv[3])){
      while(tries != 0 && check_password() == -1){
          printf("Invalid password\n");
          tries--;
      }

      if(tries == 0){
        printf("Exceeded number of tries, Please try again later\n");
        exit(1);
      }


      }else{
        printf("%s: File does not exist\n",argv[3]);
      } 
    mode = 2;
    } 
   
    key = argv[4];

    if(argv[5] != NULL){
      printf("Value argument will be dismissed\n");
    }
     
  }else if(strcmp(argv[1],"range-read") == 0){
    if(strcmp(argv[2],"-f") == 0){
      if(file_exists(argv[3])){
         while(tries != 0 && check_password() == -1){
          printf("Invalid password\n");
          tries--;
        }

        if(tries == 0){
          printf("Exceeded number of tries, Please try again later\n");
          exit(1);
        }


      }else{
        printf("%s: File does not exist\n",argv[3]);
      }

      mode = 3;
    } 
  

    key = argv[4];
    key2 = argv[5];

  }else{
    printf("Operations: add/read/range-read\n");
    exit(1);
  }
  
 
  switch (mode) {
  
    case 1:
      kv_add(fp,argv[3], key, val);
      break;
    case 2:
      kv_read(fp,argv[3], key);
      break;
    case 3:
      kv_range_read(fp,argv[3], key, key2);
      break;
    default:
      printf("use -f\n");
  }

  return 0;
}
