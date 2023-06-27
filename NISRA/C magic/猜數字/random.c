#include <stdio.h>
#include <stdlib.h>

int main()
{
    unsigned int random, key = 0;

    random = rand();
    printf("Give secret number: ");

    scanf("%d", &key);

    // 如果 key 跟 random 的 XOR 運算結果是 0xdeadbeef
    if ((key ^ random) == 0xdeadbeef)
    {
        printf("secret number is correct !!!\n");

        return 0;
    }

    printf("[Solve Helper] key XOR random = %d\n", key ^ random);
    printf("No, keep trying.\n");

    return 0;
}