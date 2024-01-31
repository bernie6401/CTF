#include <stdio.h>
#include <stdlib.h>

void win(void){
    execve("/bin/sh", 0, 0);
}

int main(){
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    puts("baby pwn challenge!");
    char str[0x20];
    gets(str);
    return 0;
}
