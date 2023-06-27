
#include <stdio.h>

int main()
{
    unsigned int money = 1000;
    unsigned int decision = 1;

    while (decision != 3)
    {
        
        printf(
            "\n\n"
            
            "|-- Omae wa mou sindeiru magic flag shop --|\n"
            "|--        Buy one get nothing ~~~       --|\n"
            "\n"
            // 印出你有多少錢
            "> Money: %d\n"
            "> Options:\n"
            // 輸入 1 可以購買神奇小旗
            ">   1 : Buy dat magic flag (price: 100000)\n"
            // 輸入 2 可以購買普普小旗
            ">   2 : Buy normie flag (price: 500)\n"
            // 輸入 3 退出程式
            ">   3 : Exit\n"
            // 印出 Input > 告訴你該輸入東西了
            "Input > "
            // 給前面印出多少錢那邊一個參數 (不然他不知道要印多少)
            , money
        );

        scanf("%d", &decision);

        if (decision == 1)
        {
            if (money > 100000)
            {
                printf("\nyou have a magic flag now.\n\n");
                return 0;
            }
            else
                printf("> NoT enOugH mOneY...\n");
        }
        else if (decision == 2)
        {
            printf("> Input the quantity u wanna buy\n");
            int qt;
            scanf("%d", &qt);
            if (qt < 0)
            {
                printf("> NOPE.\n");
                continue;
            }
            money -= (500 * qt);
            printf("> Ur money: %d\n", money);
        }
        else if (decision != 3)
            printf("> Plz input sth i can handle\n");
    }


    printf("> Bye\n");
    return 0;
}