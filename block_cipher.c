#define _GNU_SOURCE 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <inttypes.h>
#include <math.h>

/*Globals I'll need*/
//SkipJack table given in the assignment prompt
uint8_t ftable [] = 
{0xa3,0xd7,0x09,0x83,0xf8,0x48,0xf6,0xf4,0xb3, 0x21,0x15,0x78,0x99,0xb1,0xaf,0xf9,
0xe7,0x2d,0x4d,0x8a,0xce,0x4c,0xca,0x2e,0x52,0x95,0xd9,0x1e,0x4e,0x38,0x44,0x28,
0x0a,0xdf,0x02,0xa0,0x17,0xf1,0x60,0x68,0x12,0xb7,0x7a,0xc3,0xe9,0xfa,0x3d,0x53,
0x96,0x84,0x6b,0xba,0xf2,0x63,0x9a,0x19,0x7c,0xae,0xe5,0xf5,0xf7,0x16,0x6a,0xa2,
0x39,0xb6,0x7b,0x0f,0xc1,0x93,0x81,0x1b,0xee,0xb4,0x1a,0xea,0xd0,0x91,0x2f,0xb8,
0x55,0xb9,0xda,0x85,0x3f,0x41,0xbf,0xe0,0x5a,0x58,0x80,0x5f,0x66,0x0b,0xd8,0x90,
0x35,0xd5,0xc0,0xa7,0x33,0x06,0x65,0x69,0x45,0x00,0x94,0x56,0x6d,0x98,0x9b,0x76,
0x97,0xfc,0xb2,0xc2,0xb0,0xfe,0xdb,0x20,0xe1,0xeb,0xd6,0xe4,0xdd,0x47,0x4a,0x1d,
0x42,0xed,0x9e,0x6e,0x49,0x3c,0xcd,0x43,0x27,0xd2,0x07,0xd4,0xde,0xc7,0x67,0x18,
0x89,0xcb,0x30,0x1f,0x8d,0xc6,0x8f,0xaa,0xc8,0x74,0xdc,0xc9,0x5d,0x5c,0x31,0xa4,
0x70,0x88,0x61,0x2c,0x9f,0x0d,0x2b,0x87,0x50,0x82,0x54,0x64,0x26,0x7d,0x03,0x40,
0x34,0x4b,0x1c,0x73,0xd1,0xc4,0xfd,0x3b,0xcc,0xfb,0x7f,0xab,0xe6,0x3e,0x5b,0xa5,
0xad,0x04,0x23,0x9c,0x14,0x51,0x22,0xf0,0x29,0x79,0x71,0x7e,0xff,0x8c,0x0e,0xe2,
0x0c,0xef,0xbc,0x72,0x75,0x6f,0x37,0xa1,0xec,0xd3,0x8e,0x62,0x8b,0x86,0x10,0xe8,
0x08,0x77,0x11,0xbe,0x92,0x4f,0x24,0xc5,0x32,0x36,0x9d,0xcf,0xf3,0xa6,0xbb,0xac,
0x5e,0x6c,0xa9,0x13,0x57,0x25,0xb5,0xe3,0xbd,0xa8,0x3a,0x01,0x05,0x59,0x2a,0x46};
int row = 0, col = 0; //row=16, col=12, indexes of subkey matrix
uint8_t subkeys[16][12]; //This will hold on all 192 subkeys.
uint8_t key_chain[8] = {0, 0, 0, 0, 0, 0, 0, 0}; //will hold 8 bytes of key
uint16_t w0, w1, w2, w3, f0, f1, K0, K1, K2, K3; //these are global because their functions-
uint64_t key;                    //return multiple values at a time
int dec_flag = 1;
//int round = 0; 

/*Function Prototypes*/
void add_keys();
uint8_t K(int);
void get_words(FILE*, char*);
uint16_t rotl(uint16_t, int);
uint16_t rotr(uint16_t, int);
uint64_t keyrotl(uint64_t, int);
uint64_t keyrotr(uint64_t, int);
void tease_key();
uint16_t concat_bytes(uint8_t, uint8_t);
void F(uint16_t, uint16_t, int);
uint8_t get_idx(uint8_t);
uint16_t G(uint16_t,uint8_t,uint8_t,uint8_t,uint8_t);
void print_keys(); //test function to print all the generated subkeys
void print_block(uint16_t,uint16_t,uint16_t,uint16_t);

//Subroutine to go through and add subkeys of 'key' to keychain.
//Note: will have to change in decr is different than enc
void add_keys(){
   key_chain[0] = (key & 0xFF00000000000000) >> 56;
   key_chain[1] = (key & 0x00FF000000000000) >> 48;
   key_chain[2] = (key & 0x0000FF0000000000) >> 40;
   key_chain[3] = (key & 0x000000FF00000000) >> 32;
   key_chain[4] = (key & 0x00000000FF000000) >> 24;
   key_chain[5] = (key & 0x0000000000FF0000) >> 16;
   key_chain[6] = (key & 0x000000000000FF00) >> 8;
   key_chain[7] = (key & 0x00000000000000FF);    
   return;
}

/*Key function works for both encryption (input 1 for 3rd arg) and
  decryption (input 0 for 3rd arg)
*/
uint8_t K(int x){
   int idx;
   if (dec_flag){
      key = keyrotl(key, 1);
      add_keys();
      idx = x % 8;
      subkeys[row][col++] = key_chain[idx]; //add to global subkeys[][]
      if (col == 12){
         col = 0; //wrap mat col back to 0
         row++; //inc rown up 1
      }
      return key_chain[idx];      
   }
   else {
      idx = x % 8;
      uint8_t ret = key_chain[idx];
      subkeys[row][col++] = ret; //add to global subkeys[][]
      if (col == 12){
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
   printf("word 1 of pt: %hx\n", w0);
   //printf("%hu\n", (uint16_t) w1);
    
   temp1[0] = bl[4]; temp1[1] = bl[5]; temp1[2] = bl[6]; temp1[3] = bl[7];
   sscanf(temp1, "%X", &temp2);
   w1 = (uint16_t) temp2;
   printf("word 2 of pt: %hx\n", w1);      
   //printf("%hu\n", (uint16_t) w2);

   temp1[0] = bl[8]; temp1[1] = bl[9]; temp1[2] = bl[10]; temp1[3] = bl[11];
   sscanf(temp1, "%X", &temp2);
   w2 = (uint16_t) temp2;
   printf("word 3 of pt: %hx\n", w2);
   //printf("%hu\n", (uint16_t) w3);

   temp1[0] = bl[12]; temp1[1] = bl[13]; temp1[2] = bl[14]; temp1[3] = bl[15];
   sscanf(temp1, "%X", &temp2);
   w3 = (uint16_t) temp2;
   printf("word 4 of pt: %hx\n", w3);
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

//Gets 1st, 2nd, etc 16 bits from key. Tested and Working
void tease_key(){
   //DEBUG: see which order the keys need to be read in
   K3 = (key & 0x000000000000FFFF);
   K2 = (key & 0x00000000FFFF0000) >> 16;
   K1 = (key & 0x0000FFFF00000000) >> 32;
   K0 = (key & 0xFFFF000000000000) >> 48;
   return;
}

/*Subtroutine to concatenate two 8 bit unsigned ints into
  a 16 bit unsigned int*/
uint16_t concat_bytes(uint8_t a, uint8_t b){
   return ((uint16_t) a << 8) | b;
}

/*Subroutine to access value of global skpjack table.
  (This is Ftable() from homework prompt)*/
uint8_t get_idx(uint8_t val){
   uint8_t row = (val & 0xF0) >> 4;
   uint8_t col = (val & 0x0F);
   uint8_t ret = ftable[16*row + col];
   return ret;
}

/*G function from homework prompt, takes 16u bit and round
  and outputs a 16u bit concantenation of two bytes*/
uint16_t G(uint16_t w, uint8_t k1, uint8_t k2, uint8_t k3, uint8_t k4){
   uint8_t g1, g2, g3, g4, g5, g6;
   g1 = (w & 0xF0) >> 4;
   g2 = (w & 0x0F);
   g3 = get_idx(g2^k1)^g1;
   g4 = get_idx(g3^k2)^g2;
   g5 = get_idx(g4^k3)^g3;
   g6 = get_idx(g5^k4)^g4;
   return concat_bytes(g5, g6);   
}


/*F function from homework prompt to return f0 and f1 during
  each round*/
void F(uint16_t r0, uint16_t r1, int rnd){
   unsigned int mod_val = exp2(16);
   uint16_t t0, t1;

   uint8_t gk1, gk2, gk3, gk4, gk5, gk6, gk7, gk8, k9, k10, k11, k12;
   gk1 = K(4*rnd);
   gk2 = K(4*rnd+1);
   gk3 = K(4*rnd+2);
   gk4 = K(4*rnd+3);

   gk5 = K(4*rnd);
   gk6 = K(4*rnd+1);
   gk7 = K(4*rnd+2);
   gk8 = K(4*rnd+3);

   k9 = K(4*rnd);
   k10 = K(4*rnd+1);
   k11 = K(4*rnd+2);
   k12 = K(4*rnd+3);
   
   t0 = G(r0, gk1, gk2, gk3, gk4);
   t1 = G(r1, gk5, gk6, gk7, gk8);
   f0 = (t0+2*t1+concat_bytes(k9,k10)) % mod_val;
   f1 = (2*t0+t1+concat_bytes(k11,k12)) % mod_val;      
   return;
}

void print_block(uint16_t a, uint16_t b, uint16_t c, uint16_t d){
   printf("%hx %hx %hx %hx\n", a,b,c,d);
}

//test function to make sure I'm print all the keys correctly
void print_keys(){
   for (int i = 0; i < 16; i++){
     printf("row %d: ", i);
     for (int j = 0; j < 12; j++){
        printf("%2x ", subkeys[i][j]);  
     }
     printf("\n");
   }
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
   printf("Key in hex is: %lx\n", (long unsigned int) key);
   //printf("%llu\n", (long long unsigned int) key);

   uint16_t R0, R1, R2, R3; //encrypting values that will be saved per round
         
   while ((result = fread(block, 1, 16, fd)) == 16){             
          
      get_words(fd, block);

      //Whitening Step
      tease_key();
      printf("Key pieces are: ");
      print_block(K0, K1, K2, K3); 
      
      R0 = w0^K0; //XOR wi with Ki
      R1 = w1^K1;
      R2 = w2^K2;
      R3 = w3^K3;

      printf("After whitening step: ");
      print_block(R0, R1, R2, R3);
      //yi's are temps, ci's are the resulting cipher words, tempi are temps
      uint16_t y0, y1, y2, y3, c0, c1, c2, c3, temp1, temp2;      
      //Encryption Loop
      int round = 0;
      while (round < 16){

         F(R0, R1, round);
         temp1 = R2^f0; //->R0
         temp2 = R1; //->R3
         R1 = rotl(R3, 1)^f1;
         R2 = R0;
         R3 = temp2;
         R0 = temp1;
                  
      round++;
      } //done with encryption round processing

      printf("Key after 16 rounds is: %lx\n", key);
      tease_key(); //get individual 16 bit parts of newest key
      y0 = R2; y1 = R3; y2 = R0; y3 = R1;
      c0 = y0^K0;
      c1 = y1^K1;
      c2 = y2^K2;
      c3 = y3^K3;
      //ENCRYPTION DONE
      print_keys();
      printf("Encrypted block: "); 
      print_block(c0,c1,c2,c3);

                      
   }
    
   fclose(fd);//plaintext
   fclose(kd);//keytext
   
   return 0;
}
