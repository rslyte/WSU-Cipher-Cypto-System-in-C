block_cipher:
	gcc -std=c99 block_cipher.c -o block_cipher
clean:
	rm *.txt~ Makefile~ *.c~ block_cipher
