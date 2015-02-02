#define _GNU_SOURCE 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <inttypes.h>

/*Globals I'll need*/
int row = 0, col = 0; //row=16, col=12, indexes of subkey matrix
uint8_t subkeys[16][12]; //This will hold on all 192 subkeys.
uint8_t key_chain[8] = {0, 0, 0, 0, 0, 0, 0, 0}; //will hold 8 bytes of key
uint16_t w0, w1, w2, w3, f0, f1, K0, K1, K2, K3; //these are global because their functions-
uint64_t key;                    //return multiple values at a time

void add_keys();
uint8_t K(int, int);
void get_words(FILE*, char*);
uint16_t rotl(uint16_t, int);
uint16_t rotr(uint16_t, int);
uint64_t keyrotl(uint64_t, int);
uint64_t keyrotr(uint64_t, int);
void tease_key();

//Subroutine to go through and add subkeys of 'key' to keychain.
//Note: will have to change in decr is different than enc
void add_keys(){
   key_chain[7] = (key & 0xFF00000000000000) >> 56;
   key_chain[6] = (key & 0x00FF000000000000) >> 48;
   key_chain[5] = (key & 0x0000FF0000000000) >> 40;
   key_chain[4] = (key & 0x000000FF00000000) >> 32;
   key_chain[3] = (key & 0x00000000FF000000) >> 24;
   key_chain[2] = (key & 0x0000000000FF0000) >> 16;
   key_chain[1] = (key & 0x000000000000FF00) >> 8;
   key_chain[0] = (key & 0x00000000000000FF);    
   return;
}

/*Key function works for both encryption (input 1 for 3rd arg) and
  decryption (input 0 for 3rd arg)
*/
uint8_t K(int x, int flag){
   int idx;
   if (flag){
      key = keyrotl(key, 1);
      add_keys();
      idx = x % 8;
      subkeys[row][col++] = key_chain[idx]; //add to global subkeys[][]
      if (col == 16){
         col = 0; //wrap mat col back to 0
         row++; //inc rown up 1
      }
      return key_chain[idx];      
   }
   else {
      idx = x % 8;
      uint8_t ret = key_chain[idx];
      subkeys[row][col++] = ret; //add to global subkeys[][]
      if (col == 16){
         col = 0; //wrap mat col back to 0
         row--; //dec row down 1
      }
      key = keyrotr(key, 1);
      add_keys();
      return ret;
   }
}  


/*
  This function is just designed read the 16 hex character string
  and convert them to unsigned 16-bit shorts
*/
void get_words(FILE* fd, char* bl){

   char temp1[4];
   unsigned int temp2;

   temp1[0] = bl[0]; temp1[1] = bl[1]; temp1[2] = bl[2]; temp1[3] = bl[3];
   sscanf(temp1, "%X", &temp2);
   w0 = (uint16_t) temp2;      
   //printf("%hx\n", w1);
   //printf("%hu\n", (uint16_t) w1);
    
   temp1[0] = bl[4]; temp1[1] = bl[5]; temp1[2] = bl[6]; temp1[3] = bl[7];
   sscanf(temp1, "%X", &temp2);
   w1 = (uint16_t) temp2;
   //printf("%hx\n", w2);      
   //printf("%hu\n", (uint16_t) w2);

   temp1[0] = bl[8]; temp1[1] = bl[9]; temp1[2] = bl[10]; temp1[3] = bl[11];
   sscanf(temp1, "%X", &temp2);
   w2 = (uint16_t) temp2;
   //printf("%hx\n", w3);
   //printf("%hu\n", (uint16_t) w3);

   temp1[0] = bl[12]; temp1[1] = bl[13]; temp1[2] = bl[14]; temp1[3] = bl[15];
   sscanf(temp1, "%X", &temp2);
   w3 = (uint16_t) temp2;
   //printf("%hx\n", w4);
   //printf("%hu\n", (uint16_t) w4);

}

/*I got both of these functions from Wikipedia because, frankly, they
should be included as library functions in C (they already are in   assembly). I changed the type from 'unsigned int'*/
uint16_t rotl(uint16_t value, int shift) {
    return (value << shift) | (value >> (sizeof(value) * CHAR_BIT - shift));
}
uint16_t rotr(uint16_t value, int shift) {
    return (value >> shift) | (value << (sizeof(value) * CHAR_BIT - shift));
}

/*Same function but for shifting the key, couldn't figure out how to just use one
  subroutine with some kind of flag to shift a 64 bit key or a short*/
uint64_t keyrotl(uint64_t value, int shift) {
    return (value << shift) | (value >> (sizeof(value) * CHAR_BIT - shift));
}
uint64_t keyrotr(uint64_t value, int shift) {
    return (value >> shift) | (value << (sizeof(value) * CHAR_BIT - shift));
}

void tease_key(){
   K0 = (key & 0x000000000000FFFF);
   K1 = (key & 0x00000000FFFF0000) >> 16;
   K2 = (key & 0x0000FFFF00000000) >> 32;
   K3 = (key & 0xFFFF000000000000) >> 56;
   return;
}

int main(void){
  
   FILE *fd = NULL, *kd = NULL; 
   size_t result;
   char block[16];
     
   if ((fd = fopen("plaintext.txt", "r")) == NULL){
      printf("Plaintext file open failed. Exit\n");
      exit(1); 
   }

   if ((kd = fopen("key.txt", "r")) == NULL){
      printf("Key file open failed. Exit\n");
      exit(1); 
   }

   if((result = fread(block, 1, 16, kd)) != 16){
      printf("Key file not formatted properly. Exit\n");
      fclose(fd);
      exit(1);
   }
   sscanf(block, "%" SCNx64, &key);
   //printf("Key in hex is: %llx\n", (long long unsigned int) key);
   //printf("%llu\n", (long long unsigned int) key);

   uint16_t R0, R1, R2, R3; //encrypting values that will be saved per round
   int round = 0; //there will be 16 rounds here
      
   while ((result = fread(block, 1, 16, fd)) == 16){             

          
      get_words(fd, block);

      //Whitening Step
      tease_key();

      R0 = w0^K0; //XOR wi with Ki
      R1 = w1^K1;
      R2 = w2^K2;
      R3 = w3^K3;

      //Encryption Loop
      while (round < 16){


      }    
                  
   }
    
   fclose(fd);//plaintext
   fclose(kd);//keytext
   
   return 0;
}
