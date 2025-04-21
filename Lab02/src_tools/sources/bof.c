#include <stdio.h>
#include <unistd.h>

int doIt(){
        char buf[600]={ '\0' };
        int len;

        setbuf(stdout, NULL);
        printf("Enter something in English: ");
        len = read(0, buf, 1000);
        printf("You entered %d characters: %s\n", len, buf);
        return 0;
}

void main(){
        doIt();
}
