// inspired by https://samsclass.info/127/proj/ED402.htm
//
// for exploitation, must be compiled with -D_FORTIFY_SOURCE=0
// http://thexploit.com/secdev/turning-off-buffer-overflow-protections-in-gcc/

#include <stdio.h>
#include <string.h>

void hackMe(char* str) {
  char tooSmall[400];
  register int i[2] asm("rbp");

  printf("Welcome on board!\n");
  printf("So, you think you can hack me? ;o)\n");
  printf("($rbp = %#08x%08x)\n\n", i[1], i[0]);
  strcpy(tooSmall, str);
  printf("Arg1 = %s\n", str);
}

int main (int argc, char* argv[]){
  hackMe(argv[1]);
  return 0;
}
