#include <stdio.h>
#include <string.h>

void bufferSample(char* buf) {
  char smallbuf[32];
    strcpy(smallbuf, buf);
    printf("%s\n", smallbuf);
}

int main (int argc, char* argv[]){
  bufferSample(argv[1]);
  return 0;
}

