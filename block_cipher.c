#define _GNU_SOURCE 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int main(void){
  
   FILE *fd = NULL; 
   size_t result;
   char block[16];
   uint16_t w1, w2, w3, w4;
  
   if ((fd = fopen("plaintext.txt", "r")) == NULL){
      printf("Plaintext file open failed. Exit\n");
      exit(1); 
   }
   char temp1[4];
   unsigned int temp2;
   while ((result = fread(block, 1, 16, fd)) == 16){             
          
      temp1[0] = block[0];
      temp1[1] = block[1];
      temp1[2] = block[2];
      temp1[3] = block[3];
      sscanf(temp1, "%X", &temp2);
      w1 = (uint16_t) temp2;      
      printf("%hx\n", w1);
      printf("%hu\n", (uint16_t) w1);
    

      temp1[0] = block[4];
      temp1[1] = block[5];
      temp1[2] = block[6];
      temp1[3] = block[7];
      sscanf(temp1, "%X", &temp2);
      w2 = (uint16_t) temp2;
      printf("%hx\n", w2);      
      printf("%hu\n", (uint16_t) w2);

      temp1[0] = block[8];
      temp1[1] = block[9];
      temp1[2] = block[10];
      temp1[3] = block[11];
      sscanf(temp1, "%X", &temp2);
      w3 = (uint16_t) temp2;
      printf("%hx\n", w3);
      printf("%hu\n", (uint16_t) w3);

      temp1[0] = block[12];
      temp1[1] = block[13];
      temp1[2] = block[14];
      temp1[3] = block[15];
      sscanf(temp1, "%X", &temp2);
      w4 = (uint16_t) temp2;
      printf("%hx\n", w4);
      printf("%hu\n", (uint16_t) w4); 
                  
   }
    
   fclose(fd);//plaintext
   
   return 0;
}
