Assignment 1 - CS457 - csd4579 - Athanasiadis Anastasios
_________________________________________________________________________________________

* This project consists of two parts
  - cs457_crypto: A collection of encryption/decryption algorithms
  - kv: A key value add/read with an encrypted database

_________________________________________________________________________________________

* cs457_crypto:

 Usage: ./cs457_crypto <filename> <encryption type>
  <encryption types> a string that can be one of the following:
    otp
    aff 
    sub 
    tri 
    scy 
    rai

    Test files included:
      aff.txt - affine cipher tutorial example
      sub.txt - cipher given in the assignment prompt 
      tri.txt - trithemius cipher tutorial example
      scy.txt - scytale cipher tutorial example
      rai.txt - rail fence cipher tutorial example

      test1.txt - simple text
      test2.txt - test to check Uppercase and lowercase characters
      test3.txt - test to check punctuations and numbers
      text4.txt - Only punctuations
      text5.txt - Empty file

      everything.txt - Text that includes everything

_________________________________________________________________________________________
  
  Short description of every encryption type:
  1.ONE TIME PAD:
    I use dev/urandom to generate the key. And i perform the XOR operation to 
    get the ciphertext, then the same key is used to decrypt the message.

  2.AFFINE CIPHER: 
    I remove every other character except for letters and i use the affine mappings 
    char array to find out the value of x (or y in decryption) and perform the operations
    to get the encrypted/decrypted letter.

  3.SUBSTITUTION ENCRYPTION:
    The ciphertext is turned into strings of only asterisks and each letter is revealed 
    whenever the user inputs a mapping. Then the user can input a partially decrypted word
    and the word_seek function is called which searches every word in the words.txt file
    to find possible words that match the user's input.

    The word_seek function checks for the missing letters in the partially decrypted word
    and it only prints words with characters that have not been mapped yet. For example
    the input: th** will never output the word "that" because the letter T is already
    mapped. Another example is if we have mapped S, the input th** will never output 
    words like: "this" or "thus".

  4.TRITHEMIUS CIPHER:
    I use a grid with every capital letter and the shift variable that increments with
    every letter and wraps around whenever it gets out of bounds on the grid.
    I turn the Plaintext/ciphertext into only letters and then i turn every letter in Uppercase.
    Then after the encryption/decryption the buffer returns to its original format but 
    with encrypted/decrypted letters.

  5.SCYTALE CIPHER:
    I turn the buffer into just letters, and then i initialize the grid. It inserts the
    plaintext into the scytale and inserts into the ciphertext buffer by reading
    column by column. In the decryption it inserts into the plaintext buffer by reading
    the scytale row by row. Remaining cells are ignored.

  6.RAIL FENCE CIPHER:
    I turn the buffer into just letters again, and i initialize the grid. It inserts 
    each letter into the correct position of the rail and fills the rest of the cells
    of the column with dots. During encryption it reads the rail line by line and 
    during decryption it reads it column by column ignoring the dots. 

_________________________________________________________________________________________
      
  Plaintext of given ciphertext that was decrypted using the substitution decryptor

"this is a text that has been encrypted using the
affine algorithm and given as an assigment in the computer science
department of the university of crete"

=========================================================================================

*kv:

  Usage: ./kv <operation> -f <filename> <key> <value/key2>
    operations: add, read, range-read

  Checks if the file exists and if not creates it and sets a new master password.
  If it already exists it asks for the master password so we can have access to the decrypted file.

  The key and IV are generated using bytes from the master password.

  The encrypt and decrypt functions make use of the following openSSL functions for AES encryption
  and decryption respectively:
  
  encryption:   
    Firstly, I initialize the EVP_CIPHER_CTX which will contain information crucial for 
    performing the encryption.
    Then i use the EVP_EncryptInit_ex() function which initializes the encryption process, with 
    the given encryption type (AES in our case) and the given key and IV 
    Right after that the EVP_EncryptUpdate function is called, which is used to perform the 
    actual encryption. 
    Lastly we use the EVP_EncryptFinal_ex, which finalizes the process. and writes into the 
    decrypted text.
 
  decryption:
    The process is almost the same when decrypting, except the functions called are 
    EVP_DecryptInit_ex(), EVP_DecryptUpdate() and EVP_DecryptFinal_ex()
    Which do the reverse of the encryption functions mentioned above.

_________________________________________________________________________________________



