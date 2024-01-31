#include <stdio.h>
#include <stdio.h>

int main(){
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
	puts("Do you know the libc?");
	char str[0x20];
	scanf("%s", str);
	getchar();
	printf(str);
	gets(str);
	return 0;
}
