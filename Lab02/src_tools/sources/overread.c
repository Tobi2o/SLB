	#include <stdio.h>
	#include <stdlib.h>
	#include <ctype.h>

	int main() {
	char secret[8] = "S3CR3T", buf[100] = {0},*p;
	int i, len;

		while (1) {
			printf(">Enter the nb of chars:"); fflush(0);
			p = fgets(buf, sizeof(buf), stdin); if (p==NULL) return 0;
			len = atoi(p);
			printf(">Enter the content:"); fflush(0);
			p = fgets(buf, sizeof(buf), stdin); if (p==NULL) return 0;
			printf("ECHO:");
			for (i=0; i<len ;i++)
				if (!iscntrl(buf[i])) putchar(buf[i]);
				else putchar('.');
			printf("\n\n"); fflush(0);
		}
	}
	
	
