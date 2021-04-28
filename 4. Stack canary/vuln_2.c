#include <stdio.h>

int main(int argc, char *argv[]) {
	char name[16];
	char purpose[64];

	gets(name);
	printf("Hi!");
	printf(name);
	printf("\n");
	gets(purpose);
	printf("%s",purpose);
	return 0;
	
}
