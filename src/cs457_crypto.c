#include "cs457_crypto.h"

size_t length;
int grid[26][26];
char affine_mappings[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
char** scytale;
int** rail;
int* cases;
int lines;
size_t scy_len;
size_t rail_len;
int rods;
int rails; 

/* TODO: 
 *       fix words  
 */

char* create_buffer(char* filename){
  
  FILE *fp = fopen(filename, "r");
  if(!fp){
    printf("Could not open file\n");
    exit(1);
  }

  fseek(fp, 0, SEEK_END);
  size_t buf_len = ftell(fp);
  fseek(fp, 0, SEEK_SET); 

  char* buf = (char*)malloc((buf_len+1)*sizeof(char));

  size_t read = fread(buf, 1, buf_len, fp);
  buf[buf_len] = '\0';

  length = strlen(buf) - 1;
  fclose(fp);
  return buf;
  
}

char* generate_key(char* plaintext){
  char* key;
  char c;
  ssize_t len = strlen(plaintext);
  FILE *fp = fopen("/dev/urandom", "r");

  key = (char*)malloc((len+1)*sizeof(char));
  size_t read = fread(key, 1, len, fp); 
  key[len] = '\0';
  return key;
}

int count_letters(char* text){
  
  int total_letters = 0;
  for(int i = 0; i < strlen(text); i++){
    if((text[i] >= 'A' && text[i] <= 'Z') || (text[i] >= 'a' && text[i] <= 'z')){
      total_letters++;
    }
  }

  return total_letters;
}

char* convert_to_letters(char* text, int letters){
 
  char* letter_buf = (char*)malloc((letters+1)*sizeof(char));
  int k = 0;
    
  for(int i = 0; text[i] != '\0'; i++){
    if((text[i] >= 'A' && text[i] <= 'Z') || (text[i] >= 'a' && text[i] <= 'z')){
      letter_buf[k] = text[i];
      k++;
    }
  } 

  letter_buf[letters] = '\0';
  return letter_buf;
}

char* convert_to_full_buf(char* ciphertext,char* text){

  int k = 0;
  for(int i = 0; ciphertext[i] != '\0'; i++){
     if((ciphertext[i] >= 'A' && ciphertext[i] <= 'Z') || (ciphertext[i] >= 'a' && ciphertext[i] <= 'z')){
      ciphertext[i] =  text[k]; 
      k++;
     }
  }

  return ciphertext;
}

void save_case_positions(char *text){

  for(int i = 0; i < length; i++){
    if((text[i] >= 'A' && text[i] <= 'Z') || (text[i] >= 'a' && text[i] <= 'z')){ 
      if(isupper(text[i])){
        cases[i] = 2;
      }else{
        cases[i] = 1;
      }
    }else{
      cases[i] = 0;
    }
  }
}

char* retreive_case_positions(char* text){

  for(int i = 0; i < length; i++){
    if(cases[i] == 2){
      text[i] = toupper(text[i]);
    }else if(cases[i] == 1){
      text[i] = tolower(text[i]);
    }
  }

  return text;
}

char* one_time_pad_encr(char* plaintext, char* key){
  char* ciphertext;
  size_t len = strlen(plaintext);

  ciphertext = (char*)malloc((len + 1)*sizeof(char));
  for(size_t i = 0; i < len; i++){
    ciphertext[i] = plaintext[i] ^ key[i];
  }
  
  ciphertext[len] = '\0';
  return ciphertext;
}

char* one_time_pad_decr(char* ciphertext, char* key){
  char* plaintext;
  size_t len = strlen(ciphertext);

  plaintext = (char*)malloc((len + 1)*sizeof(char));
  for(size_t i = 0; i < len; i++){
    plaintext[i] = ciphertext[i] ^ key[i];
  }

  plaintext[len] = '\0';
  return plaintext;
}



char* affine_encr(char* plaintext){
  
  char* ciphertext;
  char* encr_text;
  size_t len = strlen(plaintext) - 1;
  int x = -1;

  save_case_positions(plaintext);
 
  ciphertext = (char*)malloc((len+1)*sizeof(char));

  int letters = count_letters(plaintext);
  encr_text = convert_to_letters(plaintext,letters);

  for(size_t i = 0; encr_text[i] != '\0'; i++){
   
    encr_text[i] = toupper(encr_text[i]);
    x = -1;
    for(int j = 0; j < strlen(affine_mappings); j++){

      if(encr_text[i] == affine_mappings[j]){
        x = j;
        break;
      }

    }
  
    if(x == -1){
      continue;
    }

    x = 5*x;
    x = x + 8;
    x = x % 26;

 
    encr_text[i] = affine_mappings[x];
  }

  ciphertext = convert_to_full_buf(plaintext, encr_text);
  ciphertext[len] = '\0';

  ciphertext = retreive_case_positions(ciphertext);
  
  free(encr_text);
  return ciphertext;
}


char* affine_decr(char* ciphertext){
  char* plaintext;
  size_t len = strlen(ciphertext);
  int y = -1;
  char* decr_text;

  plaintext = (char*)malloc((len+1)*sizeof(char));

  save_case_positions(ciphertext);
  
  int letters = count_letters(ciphertext);
  decr_text = convert_to_letters(ciphertext,letters);

  for(size_t i = 0; decr_text[i] != '\0'; i++){

    decr_text[i] = toupper(decr_text[i]);
    y = -1;
    for(int j = 0; j < strlen(affine_mappings); j++){
      if(decr_text[i] == affine_mappings[j]){
        y = j;
        break;
      }

    
    }
    
    if(y == -1){
      continue;
    }
    
    y = y - 8;
    y = y*21;
    y = y % 26;

    if(y < 0){
      y += 26;
    }
    
    decr_text[i] = affine_mappings[y];
  }

  plaintext = convert_to_full_buf(ciphertext, decr_text);
  plaintext[len] = '\0';
   
  plaintext = retreive_case_positions(plaintext);
  free(decr_text);
  return plaintext;
}

int not_deciphered(char *plaintext){
  for(size_t i = 0; i < length; i++){
    if(plaintext[i] == '*'){
      return 1;
    }
  }

  return 0;
}


char* substitution_decr(char* ciphertext){
  char* plaintext = (char*)malloc(length*sizeof(char)); 
  strncpy(plaintext,ciphertext,length);
  char mapping[10];
  char pattern[100];
  char from;
  char to;

  for(size_t i = 0; i < length; i++){
    if(ciphertext[i] >= 'A' && ciphertext[i] <= 'z'){
      ciphertext[i] = tolower(ciphertext[i]);
      plaintext[i] = '*'; 
    }else if (ciphertext[i] == ' '){
      plaintext[i] = ' ';
    }else{
      plaintext[i] = ciphertext[i];
    }
  }

  while(not_deciphered(plaintext)){
    printf("\n%s\n",plaintext);
    printf("\nMapping: ");
    
    if(fgets(mapping, sizeof(mapping), stdin) == NULL){
      return plaintext;
    }

    to = mapping[0];
    from = mapping[3];
    
    for(size_t i = 0; i < length; i++){
      if(ciphertext[i] == from){
        plaintext[i] = to;
      }
    }
   
    printf("\n%s\n",plaintext);
    printf("\nEnter partially decrypted word: ");
    fgets(pattern, 100, stdin);
    pattern[strcspn(pattern,"\n")] = '\0';

    printf("pattern = %s\n", pattern);
    word_seek(pattern,plaintext);

  }   
  
  return plaintext;
}


void word_seek(char *partial,char* plaintext) {
    
      
    FILE *file = fopen("utils/words.txt", "r"); 
    printf("Possible words:\n");
    int print = 1;
   
    int k = 0;
    char word[100];
    while (fgets(word, 100, file) != NULL) {
               
        word[strcspn(word,"\n")] = '\0';
        
        int i = 0;
        if(strlen(word) == strlen(partial)){
          while(partial[i] == '*' || partial[i] == word[i]){
            i++;
          }
        }else{
          continue;
        }
        
       
        if(partial[i] == '\0'){
          print = 1;
          for(k = 0; partial[k] != '\0'; k++){
            if(partial[k] != '*'){
              continue;
            }else{
              if(strchr(plaintext, word[k]) != NULL){
                print = 0;
                break;
              }
            }
          }

          if(print == 1){
           printf("word = %s\n", word);
   
          }
        }


    }   

    

    fclose(file);
}

void grid_init(){

  int j,k = 0;
  for(int i = 0; i < 26; i++){
    j = i;
    k = 0;
    while(k < 26){
      grid[i][k] = 'A' + j;
      if(j == 25){
        j = 0;
      }else{
        j++;
      }
      k++;
    } 
  }

}

int corresponding(char letter){
  
  for(int i = 0; i < 26; i++){
    if(letter == 'A' + i){
      return i;
    }
  }

  return -1;
}



char* trithemius_encr(char* plaintext){

  char* ciphertext = (char*)malloc((length+1)*sizeof(char));
  int shift = 0;
  int val;

  save_case_positions(plaintext);

  int letters = count_letters(plaintext);
  char* encr_text = convert_to_letters(plaintext,letters);

  for(size_t i = 0; encr_text[i] != '\0'; i++){
    val = corresponding(toupper(encr_text[i]));
    if(val == -1){ continue; }
    
    encr_text[i] = grid[val][shift];

    if(shift == 25){
      shift = 0;
    }else{
      shift++;
    }

  }

  ciphertext = convert_to_full_buf(plaintext, encr_text);
  ciphertext[length] = '\0';

  ciphertext = retreive_case_positions(ciphertext);


  return ciphertext;
}

char* trithemius_decr(char* ciphertext){

  char* plaintext = (char*)malloc((length+1)*sizeof(char));
  int shift = 0;
  int val;

  save_case_positions(ciphertext);
  char* decr_text = convert_to_letters(ciphertext, count_letters(ciphertext));

  for(size_t i = 0; decr_text[i] != '\0'; i++){
    val = corresponding(toupper(decr_text[i]));
    if(val == -1){ continue; }    

    val = val - shift;
    if(val < 0){
      val = 26 + val;
    }

    decr_text[i] = grid[0][val];
    
    if(shift == 25){
      shift = 0;
    }else{
      shift++;
    }
  }

  plaintext = convert_to_full_buf(ciphertext, decr_text);
  plaintext[length] = '\0';
  
  plaintext = retreive_case_positions(plaintext);
 
  return plaintext;
}



void scytale_init(int rods,size_t len){
  
  if((len % rods) == 0){
    lines = len / rods;
  }else{
    lines = (len / rods) + 1;
  }
  
  scytale = (char**)malloc(lines*sizeof(char*));
 
  for(int i = 0; i < lines; i++){
    scytale[i] = (char*)malloc(rods * sizeof(char));
  }

  scy_len = len;

}

char* scytale_encr(char* plaintext){
  
  int k = 0;
  char* ciphertext = (char*)malloc((length+1)*sizeof(char));

  char* encr_text = convert_to_letters(plaintext, count_letters(plaintext));

  scytale_init(rods, strlen(encr_text));

  for(int i = 0; i < lines; i++){
    for(int j = 0; j < rods; j++){
      if(k < scy_len){
        scytale[i][j] = encr_text[k];
        k++;
      }else{
        scytale[i][j] = ' ';
      }
    }
  }

  k = 0;
  for(int j = 0; j < rods; j++){
    for(int i = 0; i < lines; i++){
      if(scytale[i][j] != ' '){
        encr_text[k] = scytale[i][j];
        k++;
      }
    }
  }
   
  ciphertext = convert_to_full_buf(plaintext, encr_text);
  ciphertext[length] = '\0';

  return ciphertext;
}


char* scytale_decr(char* ciphertext){
  
  char* plaintext = (char*)malloc((length+1)*sizeof(char));
  int k = 0;

  char* decr_text = convert_to_letters(ciphertext, count_letters(ciphertext));

  for(int i = 0; i < lines; i++){
    for(int j = 0; j < rods; j++){
      if(scytale[i][j] != ' '){
        decr_text[k] = scytale[i][j];
        k++;
      }
    }
  }

  plaintext = convert_to_full_buf(ciphertext, decr_text);
  plaintext[length] = '\0';

  return plaintext;
}


void rail_init(int rails,size_t len){
  
  rail = (int**)malloc(rails*sizeof(int*));

  for(int i = 0; i < rails; i++){
    rail[i] = (int*)malloc(len*sizeof(int));
  }

  rail_len = len;

}

char* rail_fence_encr(char* plaintext){
  
  char* ciphertext = (char*)malloc((length+1)*sizeof(char));
  int i,k = 0;
  int direction = 0;
  int down = 1;
 
  char* encr_text = convert_to_letters(plaintext, count_letters(plaintext));

  rail_init(rails, strlen(encr_text));
  for(size_t i = 0; encr_text[i] != '\0'; i++){
    rail[k][i] = encr_text[i];

    for(size_t j = 0; j < rails; j++){
      if(j != k){
        rail[j][i] = '.';
      }
    }

    direction++;
    if(direction == rails){
      if(down){
        down = 0;
      }else{
        down = 1;
      }

      direction = 1;
    }

    if(down){
      k++;
    }else{
      k--;
    }

  }

  k = 0;
  for(i = 0; i < rails; i++){
    for(int j = 0; j < rail_len; j++){
      if(rail[i][j] != '.'){
        encr_text[k] = rail[i][j];
        k++;
      }
    }
  }

  ciphertext = convert_to_full_buf(plaintext, encr_text);

  ciphertext[length] = '\0';
  return ciphertext;

}

char* rail_fence_decr(char* ciphertext){
  
  char* plaintext = (char*)malloc((length+1)*sizeof(char));
 
  char* decr_text = convert_to_letters(ciphertext, count_letters(ciphertext));
  
  size_t j = 0;
  for(size_t i = 0; i < rails; i++){
    for(j = 0; j < rail_len; j++){
      if(rail[i][j] != '.'){
        decr_text[j] = rail[i][j];
      }
    }
  }

  plaintext = convert_to_full_buf(ciphertext, decr_text);
  plaintext[length] = '\0';
  return plaintext;

}

int main(int argc, char** argv){
  
  if(argc != 3){
    printf("Argument error\nUsage: ./assign1_4579 <filename> <encryption>\n"); 
    exit(1);
  }
  
  char* ptext_buf = create_buffer(argv[1]);
 
  cases = (int*)malloc((length)*sizeof(int));
 
  if(strncmp(argv[2], "otp", 3) == 0){
   
    printf("---------- One time pad cipher ----------\n");
    char* key = generate_key(ptext_buf);
    printf("key(len %lu) = %s\n", strlen(key),key);
    char* ciphertext = one_time_pad_encr(ptext_buf, key);
    printf("ciphertext = ");
    for(int i = 0; i < strlen(ciphertext); i++){
      printf("%02x ", ciphertext[i]);
    }
    printf("\n");
    char* plaintext = one_time_pad_decr(ciphertext, key);
    printf("plaintext= %s\n", plaintext);

    free(key);
    free(ciphertext);
    free(plaintext);

    printf("-----------------------------------------\n");

  }else if(strncmp(argv[2], "aff", 3) == 0){
  
    printf("-------------- Affine cipher -------------\n");
    char* ciphertext = affine_encr(ptext_buf);
    printf("ciphertext = %s\n", ciphertext);
    char* plaintext = affine_decr(ciphertext);
    printf("\nplaintext = %s\n", plaintext);
    printf("-----------------------------------------\n");
    //free(ciphertext);
    //free(plaintext);

  }else if(strncmp(argv[2], "sub", 3) == 0){
  
    printf("--------- Substitution cipher -----------\n");
    char* plaintext = substitution_decr(ptext_buf);
    printf("plaintext = %s\n", plaintext);
    printf("-----------------------------------------\n");

  }else if(strncmp(argv[2], "tri", 3) == 0){
  
    printf("----------- Trithemius cipher ------------\n");
    grid_init();
    char* ciphertext = trithemius_encr(ptext_buf);
    printf("ciphertext = %s\n", ciphertext);
    char* plaintext = trithemius_decr(ciphertext);
    printf("plaintext = %s\n", plaintext);
    printf("------------------------------------------\n");

    //free(ciphertext);
    //free(plaintext);

  }else if( strncmp(argv[2], "scy", 3) == 0){

    printf("Enter number of rods\n");
    char input[1024];
    fgets(input, 1024, stdin);
    rods = atoi(input);
  

    printf("------------ Scytale cipher --------------\n");
    char* ciphertext = scytale_encr(ptext_buf);
  
    int k = 0;
    for(int i = 0; i < lines; i++){
      for(int j = 0; j < rods; j++){
        if(k >= scy_len){
          continue;
        }

        if(scytale[i][j] != ' '){
          printf(" %c ", scytale[i][j]);
        }
        k++;
      }
      printf("\n");
    }

    printf("ciphertext = %s\n", ciphertext);
    char* plaintext = scytale_decr(ciphertext);
    printf("plaintext = %s\n", plaintext);
    printf("------------------------------------------\n");

    //free(ciphertext);
    //free(plaintext);

  }else if(strncmp(argv[2], "rai", 3) == 0){

    printf("Enter number of rails\n");
    char input[1024];
    fgets(input, 1024, stdin);
    rails = atoi(input);

    printf("----------- Rail Fence cipher -------------\n");
    char* ciphertext = rail_fence_encr(ptext_buf);
    for(int i = 0; i < rails; i++){
      for(int j = 0; j < rail_len; j++){
        printf(" %c ", rail[i][j]);
      }
      printf("\n");
    }
    printf("ciphertext = %s\n", ciphertext);
    char* plaintext = rail_fence_decr(ciphertext);
    printf("plaintext = %s\n", plaintext);
    printf("-----------------------------------------\n");

    //free(ciphertext);
    //free(plaintext);

  }else{
    printf("Argument error: Invalid encryption type\n");
    exit(1);
  }

  free(ptext_buf);
  return 0;
}
