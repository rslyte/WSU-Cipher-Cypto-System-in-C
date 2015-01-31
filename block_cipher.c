#define _GNU_SOURCE 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <inttypes.h>

/*Globals I'll need*/
//4 quarters of 64 bit block
uint16_t w1, w2, w3, w4;
uint64_t key;

/*
  This function is just designed read the 16 hex character string
  and convert them to unsigned 16-bit shorts
*/
void get_words(FILE* fd, char* bl){

   char temp1[4];
   unsigned int temp2;

   temp1[0] = bl[0]; temp1[1] = bl[1]; temp1[2] = bl[2]; temp1[3] = bl[3];
   sscanf(temp1, "%X", &temp2);
   w1 = (uint16_t) temp2;      
   printf("%hx\n", w1);
   printf("%hu\n", (uint16_t) w1);
    
   temp1[0] = bl[4]; temp1[1] = bl[5]; temp1[2] = bl[6]; temp1[3] = bl[7];
   sscanf(temp1, "%X", &temp2);
   w2 = (uint16_t) temp2;
   printf("%hx\n", w2);      
   printf("%hu\n", (uint16_t) w2);

   temp1[0] = bl[8]; temp1[1] = bl[9]; temp1[2] = bl[10]; temp1[3] = bl[11];
   sscanf(temp1, "%X", &temp2);
   w3 = (uint16_t) temp2;
   printf("%hx\n", w3);
   printf("%hu\n", (uint16_t) w3);

   temp1[0] = bl[12]; temp1[1] = bl[13]; temp1[2] = bl[14]; temp1[3] = bl[15];
   sscanf(temp1, "%X", &temp2);
   w4 = (uint16_t) temp2;
   printf("%hx\n", w4);
   printf("%hu\n", (uint16_t) w4);

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
   sscanf(block, "%" SCNx64, &key); //XXX need to figure out how to do this
   

      
   while ((result = fread(block, 1, 16, fd)) == 16){             
          
      get_words(fd, block);    
                  
   }
    
   fclose(fd);//plaintext
   fclose(kd);//keytext
   
   return 0;
}
