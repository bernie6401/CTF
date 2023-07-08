#include"stdio.h"
#include"string.h"
#include"stdlib.h"

void XOR(char* key, char* plaintext, char* ciphertext, int textSize){
  int keySize = strlen(key);
  for(int i=0; i<textSize; i++){
    ciphertext[i] = plaintext[i] ^ key[i%keySize];
  }
}

int main(){
  char ciphertext[] = "\x2c\x39\x32\x33\x24\x33\x2a\x1d\x26\x07\x04\x27\x06\x1a\x00\x22\x3e\x1d\x2b\x0b\x05\x00\x2c\x06\x2a\x0f\x00\x1a\x00\x2d\x0b\x19\x1f\x4b\x22";
  char key[] = "just_a_str";
  char* plaintext = malloc(sizeof(char)*35);
  XOR(key, ciphertext, plaintext, 35);
  printf("%s\n", plaintext);
  free(plaintext);
  return 0;
}
