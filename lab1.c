/*
** Jason Allen
**
** This program uses OpenSSL to demonstrate an attack where the attacker uses
** knowledge of the plaintext, the iv, and potential keys to learn what the
** actual key used for encryption was.  See Lab1.pdf #7
**
** to run, type 'make' in a unix shell, then supply arguments to argv[1] and argv[2]
**
** argv[1] - a formatted array of data for the ciphers.  Line 1 = the plainText
** Line 2 = the encrypted ciphertext in hex form.  Line 3 = the iv in hex form
** (see cipherData for an example).
**
** argv[2] - a list of english words under 16 characters long.  Each line should
** contain a different word (see words.txt for an example).
**
** demo - ./findkey cipherData words.txt
*/
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define KEY_LENGTH 16
#define BUFF_SIZE 256

void *addKeyPadding(unsigned char *key);
void asciiToHex(unsigned char *key);
char *convertCipherToHex(char *cipherText, int cipherLength);
unsigned char* convertToAscii(unsigned char *string);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char* plainText);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char* cipherText);
void handleErrors();
static unsigned char hexdigit2int(unsigned char xd);
char** readFile(char *fileName, int numLines);

int main(int argc, unsigned char *argv[])
{
  int wordListSize = 25143; // this should probably be passed in via argv[3]
  unsigned char** cipherData = (unsigned char**)readFile(argv[1], 3);
  unsigned char** wordList = (unsigned char**)readFile(argv[2], wordListSize);
  unsigned char* plainText = cipherData[0];
  unsigned char* cipherText = cipherData[1];
  unsigned char* iv = cipherData[2];
  unsigned char* ivAscii = convertToAscii(iv);
  // must convert the iv to ascii before processing in OpenSSL,
  // I lost a lot of sleep over this

  printf("\nplaintext: %s\n", plainText);
  printf("ciphertext: %s\n", cipherText);
  printf("iv: %s\n", iv);
  printf("iv in ascii: %s\n\n", ivAscii);

  for(int i = 0; i < wordListSize; i++)
  {
    // loop through each word in the list and add padding
    addKeyPadding(wordList[i]);

    // allocate memory to hold cipher returned from encrypt function
    unsigned char *newCipherText = calloc(BUFF_SIZE, sizeof(unsigned char));

    // encrypt the plaintext with the padded key and the iv
    // encryption returns the length of the cipher and fills newCipherText
    int cipherLength = encrypt(plainText, strlen(plainText), wordList[i], ivAscii, newCipherText);

    // convert the ciphertext into hexadecimal format, since our original is in this form
    unsigned char *cipherToCheck = convertCipherToHex(newCipherText, cipherLength);

    // check to see if they match.  If they do, we know the current key was used for encryption
    if(strcmp(cipherText, cipherToCheck) == 0){
      printf("found!\nOriginal Cipher: %s\nFound Cipher: %s\nKey Used: %s\n\n", cipherText, cipherToCheck, wordList[i]);
      free(newCipherText);\
      free(cipherToCheck);
      free(wordList[i]);
      break;
    }

    free(newCipherText);
    free(cipherToCheck);
    free(wordList[i]);
  }

  return 0;
}
/* ======================== addKeyPadding ====================
/* Adds padding to a key to make it 16 bytes, if necessary
/*
/* @param key - a key in ascii format(unsigned char*)
/* @returns void, new value is copied directly to array
*/
void *addKeyPadding(unsigned char *key)
{
  int paddingToAdd = KEY_LENGTH - strlen(key);

  for (int i = 0; i < paddingToAdd; i++){ strcat(key, "#"); }
}
/* ======================== asciiToHex =================
/* Converts an ascii key to hex
/*
/* @param key - a key in ascii(unsigned char*)
/* @returns void, new value is copied directly to array
*/
void asciiToHex(unsigned char *key)
{
  unsigned char *hexString = calloc(BUFF_SIZE, sizeof(unsigned char));

  for(int i = 0; i < strlen(key); i++){
    sprintf(hexString+i*2, "%02X", key[i]);
  }

  strcpy(key, hexString);
  free(hexString);
}
/* ============================= convertToAscii ==========================
/* Converts a hex string to Ascii
/*
/* @param string - a string in hex format (unsigned char*)
/* @returns a string in ascii characters (unsigned char*)
*/
unsigned char* convertToAscii(unsigned char *string)
{
  unsigned char* newString = calloc(BUFF_SIZE, sizeof(char));
  int length = strlen(string), k = 0, count = 0;
  char buf = 0;

  unsigned char *src = string;
  unsigned char *dst = newString;

  while (*src != '\0')
  {
    unsigned char high = hexdigit2int(*src++);
    unsigned char low  = hexdigit2int(*src++);
    *dst++ = (high << 4) | low;
  }

  *dst = '\0';

  return newString;
}
/* ============================= hexdigit2int ============================
/* converts a hex digit into an integer
/*
/* @param xd - character to conver (unsigned char)
/* @returns the character as in intger (unsigned char)
*/
static unsigned char hexdigit2int(unsigned char xd)
{
  if (xd <= '9')
    return xd - '0';
  xd = tolower(xd);
  if (xd == 'a')
    return 10;
  if (xd == 'b')
    return 11;
  if (xd == 'c')
    return 12;
  if (xd == 'd')
    return 13;
  if (xd == 'e')
    return 14;
  if (xd == 'f')
    return 15;
  return 0;
}
/* ============================= encrypt ==========================
/* Encrypts a file using OpenSSL
/*
/* @param plainText - the unencrypted plaintext (unsigned char *)
/* @param plaintext_len - the length of the plaintext (int)
/* @param key - the key used for encryption (unisigned char *)
/* @param iv - the initialization vector (unisigned char *)
/* @param cipherText - a pre-allocated empty string (unsigned char*)
/* @returns the length of the encrypted ciphertext (int)
/*
/* NOTE: All values must be passed in as ASCII!!!!
*/
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors("Encrypt cipher creation failed");

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors("Encrypt_Init failed");

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors("Encrypt_Update failed");

    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors("Encrypt_Final failed");

    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}
/* ============================= decrypt ==========================
/* Decrypts a file using OpenSSL
/*
/* @param cipherText - the encrypted ciphertext (unsigned char *)
/* @param ciphertext_len - the length of the ciphertext (int)
/* @param key - the key used for encryption (unisigned char *)
/* @param iv - the initialization vector (unisigned char *)
/* @param plainText - a pre-allocated empty string (unsigned char*)
/* @returns the length of the unencrypted plaintext (int)
*/
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    int plaintext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors("Decrypt cipher creation failed");

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors("Decrypt_Init failed");

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors("Decrypt_Update failed");

    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
     {
        //handleErrors("Decrypt_Final failed");
     }

    plaintext_len += len;

    plaintext[plaintext_len] = '\0';

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
/* ====================== readFile =========================
/* Converts the raw ASCII output into hex by dumping to a
/* file with BIO_dump_fp and then processing the output
/*
/* @param fileName - the name of the file (char *)
/* @param numLines - the number of lines in the file (int)
/* @returns an array of each line in the file (Char **)
*/
char** readFile(char *fileName, int numLines)
{
  FILE *input = fopen(fileName, "rb");
  char **returnArray = calloc(numLines, sizeof(char*));
  size_t line_buf_size = 0;
  size_t total_line_buff_size = 0;
  int line_count = 0;
  ssize_t line_size = 0;
  int i = 0;

  if(input == NULL)
  {
      printf("\n cannot open file %s", fileName);
      exit(1);
  }
  else
  {
      while (line_size >= 0)
      {
        char *line_buf = NULL;
        line_size = getline(&line_buf, &line_buf_size, input);

        if(line_size < 0)
          continue;

        line_buf[strlen(line_buf) - 1] = 0;

        returnArray[line_count] = line_buf;

        line_count++;

        total_line_buff_size += line_buf_size;
      }

      fclose(input);

      return returnArray;
  }
}
/* =================== convertCipherToHex =================
/* Converts the raw ASCII output into hex by dumping to a
/* file with BIO_dump_fp and then processing the output
/*
/* @param cipherText - the encrypted ciphertext (char *)
/* @param cipherLength - the length of the cipherData (int)
/* @returns the cipherText in hex format (Char *)
*/
char *convertCipherToHex(char *cipherText, int cipherLength)
{
    FILE *output = fopen("output.txt", "wb");

    BIO_dump_fp (output, (const char *)cipherText, cipherLength);

    fclose(output);

    /* block size is multiples of 16, hex form will always be double the block size
       so we multiply the length by 2 and then divide by 32 to get the number of
       lines that will be in the output.txt file */
    int lineCount = (cipherLength * 2) / 32;
    unsigned char **cipherData = (unsigned char**)readFile("output.txt", lineCount);
    unsigned char *hexCipher = calloc(BUFF_SIZE, sizeof(char));
    int charCount = 0, currentLineCount = 0;

    // start at i = 5 because there is alot of noise in the BIO_dump_fp output.
    // we skip the first few numbers that are irrelevant by starting at 5.
    for(int i = 5; i < strlen(cipherData[currentLineCount]); i++)
    {
        unsigned char currentChar = cipherData[currentLineCount][i];
        if(currentChar != ' ' && currentChar != '-')
        {
            hexCipher[charCount] = currentChar;
            charCount++;

            // each hex block will be in sizes of 32, when 32 characters reached,
            // go to the next array index (next line of the file)
            if(charCount % 32 == 0)
            {
              currentLineCount++;
              i = 5;

              if(currentLineCount == lineCount)
                break;
            }
        }
    }
    return hexCipher;
}

void handleErrors(char *message)
{
  printf("\n%s\n", message);
}
