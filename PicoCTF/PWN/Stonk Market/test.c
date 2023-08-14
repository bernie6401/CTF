#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int main(int argc, char *argv[])
{
    setbuf(stdout, NULL);
    char *user_buf = malloc(300 + 1);
    scanf("%300s", user_buf);
    printf(user_buf);

    exit(0);
}