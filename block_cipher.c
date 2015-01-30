#define _GNU_SOURCE 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void){
  
   FILE *fd = NULL; 
   size_t result;
   char block[16];
   unsigned int w1, w2, w3, w4;
  
   if ((fd = fopen("plaintext.txt", "r")) == NULL){
      printf("Plaintext file open failed. Exit\n");
      exit(1); 
   }
   char temp[4];
   while ((result = fread(block, 1, 16, fd)) == 16){             
      //print_hex(block); DEBUG     
      temp[0] = block[0];
      temp[1] = block[1];
      temp[2] = block[2];
      temp[3] = block[3];
      sscanf(temp, "%X", &w1);      
      printf("%X\n", (unsigned int) w1);

      temp[0] = block[4];
      temp[1] = block[5];
      temp[2] = block[6];
      temp[3] = block[7];
      sscanf(temp, "%X", &w2);      
      printf("%X\n", (unsigned int) w2);

      temp[0] = block[8];
      temp[1] = block[9];
      temp[2] = block[10];
      temp[3] = block[11];
      sscanf(temp, "%X", &w3);
      printf("%X\n", (unsigned int) w3);

      temp[0] = block[12];
      temp[1] = block[13];
      temp[2] = block[14];
      temp[3] = block[15];
      sscanf(temp, "%X", &w4);
      printf("%X\n", (unsigned int) w4); 
                  
   }
    
   fclose(fd);//plaintext
   
   return 0;
}
