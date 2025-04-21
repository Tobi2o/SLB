/*
Title:  Linux x86-64, run shell code
Author:  JEB

!!!WARNING: compile with -z execstack ;) !!!

Disassembly of section .text:
(TBD)

Bytes string:
(TBD)

*/

#include <stdio.h>
#include <string.h>

int main()
{
  char shellcode[] = "(TBD)"
                   "(TBD)"
                   "(TBD)"
                   "(TBD)";
  fprintf(stdout,"Length: %d\n",strlen(shellcode));
  (*(void  (*)()) shellcode)();
}
