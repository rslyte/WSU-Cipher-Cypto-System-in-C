**Ryan Slyter**
**ryan.slyter100@email.wsu.edu**
**Securities, program 1**

**Description**
- Modified feistel cipher which reads in characters representing hex values, encypts/decrypts, and then writes the result to a file.
 
**In this archive**
- Makefile: 'make clean' will delete exec and Makefile~ if there is one
- block_cipher.c: source code.
- plaintext.txt: test file. You can c/p the block that in there and add hex characters to test those requirements

**How to Run**
- The usual 'make', then './block_cipher 1 plaintext.txt [testfile2.txt] [testfilen.txt] > test.txt (or whatever result file you want)
- The first argument, 1, is for encryption and 0 is for decryption.

**What doesn't work correctly**
- padding works fine for encryption, for decryption there is a placement of 0's around the original hex character that is off. I couldn't figure out how to fix that, and need to turn this in and start working on other programs.

**Testing Environment**
- Final version was tested on Kali Linux 64 bit kernel version 3.18 (debian-based OS). Almost all variables and function calls are portable types.
- Previous version of the program was tested on the school server (encryption).
