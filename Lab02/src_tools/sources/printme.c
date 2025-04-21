
  void vuln(char *s) {
    int v_ebp;
    char smallbuf[32];

    asm("movl %%ebp, %0\n"
        :"=r"(v_ebp));
    printf("Value in ebp %x\n", v_ebp);

    strcpy(smallbuf, s);
    printf("%s\n", smallbuf);
  }

  int main(int argc, char *argv[]){
 
    vuln(argv[1]);
    return 0; 
  }

