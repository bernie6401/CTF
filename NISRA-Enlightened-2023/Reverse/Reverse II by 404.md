# Reverse II by 404

:::danger
請愛惜共筆，勿進行惡意刪減
:::

:::info

簡報連結：https://drive.google.com/file/d/1kkses1__PO9Tqx374yX9JJsjK-pJGEA9/view
:::
## What's Reverse 
### What's Reverse 1/3
- 把執行檔盡可能的還原成原始碼，來達到分析演算法、挖掘程式漏洞等目的

### What's Reverse 2/3
- 編譯 Compile
    - 原始碼翻譯成 Assembly 組合語言
<!--  要小心老葉會考  -->
- 組譯 Assembly
    - 組語到binary 
### What's Reverse 3/3
- Sauce compile assembly executable

- 反編譯
   - 把程式碼翻譯成虛擬碼 Pseudocode
- 反組譯 Decompile
   - 把執行檔翻譯成**組合語言**


![](https://i.imgur.com/jNexmW1.png)

>我們的電腦很笨[name=404]
>我們是逆著車流開的危險駕駛[name=404]
## review
- 變數 Variable?
	- 我們要處理的會因為時間 and/or 運算改變值的資料
- 函式 Function?
    - 國中數學課提到的小箱子
- 參數 Parameter?
	- 餵給函式、讓函式運算輸出的依據

## Common Data type
- BYTE = 1byte
	- ex. char 字元
- WORD = 2bytes
- DWORD = 4 bytes
    - ex: int in C/C++
- QWORD = 8 bytes

## Registers 
- 小但快
- CPU 內的儲存空間
- E**A**X, E**B**X, E**C**X, E**D**X
	- 儲存資料、傳遞參數......
- E**B**P,E**S**P ~base~ ~pointer/stack~ ~pointer~
	- base/stack pointer
	- 開 stack 用
- E**I**P
	- isntruction pointer
	- 指向**下一個**要執行的指令
- CPU 不能直接操作記憶體,要用暫存器過度

- 不同大小的暫存器(其實是同一個拉ㄏㄏ)
	- R 開頭 : rax, rbx ... : 64 bits
	- E 開頭 : eax, ebx ... : 32 bits
	- 沒開頭：ax, bx... : 16 bits 
	- L、H結尾：al, bl, ah, bh...: 8 bits  
## Flags
- 也是 Register 的一種
- 儲存指令運算完的結果
- Zero Flag（ZF）
	- 結果為 0：ZF = 1
	- 結果為 1：ZF = 0
- Sign flag (SF)
    - 正數: 0 、負數 : 1
    - 數字在二進位表示法時的第一個 bit
- Carry Flag（CF）
	- 無號數運算溢位時 CF = 1
- Overflow flag (OF)
    - 有號數運算溢位時 OF = 1 反之為 0 
    - OF = CF $\oplus$ SF ~~必考。真的。記住就對了。~~

## Instructions
### Instructions 1/6
- mov, movzx
	- mov dest, sauce
		- dest：目標
		- sauce：來源
	- movzx 會把 sauce 大小擴充成和 dest 一樣
    - mov eax,1
        - C:eax=1 

### Instructions 2/6
- 將後值賦給前值，必有一位為暫存器
    - mov 暫存器, 常數
    - mov 記憶體, 常數
    - mov 暫存器, 暫存器
    - mov 暫存器, 記憶體
    - mov 記憶體, 暫存器
    - ~~mov 記憶體, 記憶體~~


### Instruction 3/6
- add, sub
    - add a,b
        - a=a+b
    - sub a,b
        - a=a-b      
- inc ,dec
    - inc a
        - a++
    - dec a
        - a--  

- lea
	- 取變數的記憶體位址
	- lea int_ptr, int_var：int
- test, and
    - 位元and運算
        - test只會動flag 
        - and會改變數和flag
- cmp
	- 比較兩數誰大誰小
	- 前面減後面，結果不會寫回暫存器
	- 會改變 flag，可搭配 jmp 等跳轉指令
	- cmp a,b 
	    - 看 a-b 的結果 但 a 和 b 的值不會改變
	    - if(a>b) 判斷完 a,b 都是原來的值
    - and, or, xor
    - ~~計算機概論bj4~~ 

## 邏輯運算
- 需要兩個運算元/變數
- AND
    - 當兩個變數都是 1 : 輸出 1 當結果
- OR 
    - 只要有變數是 1 : 輸出 1 當結果
- XOR 
    - 兩個變數長得不一樣 : 輸出 1 當結果

## Conditional Jump
- JMP
    - jump label
        - lable:一個記憶體位置
    - 直接跳 
- JZ,JE
    - jump if **Z**F = 1/ **e**qual 
- JNZ, JNE
    - jump if **Z**F = **0**/ **n**ot **e**qual
- JG,JGE
    - jump if >/>=
    - 有號數(第一個位元是符號) 
- JA,JAE
    - jump if >/>=
    - 無號數(第一個位元是數字)
        - 負數永遠大於正數(負數1開頭)
- JL
    - jump if **l**ess (<)
- JLE
    - jump if **l**ess or **e**qual (<=)
- JB (無號數)
    - jump if **b**elow (<)
- JBE (無號數)
    - jump if **b**elow or equal (<=) 

## Reminder
- 有兩個運算子的指令，其中一個一定要式和暫存器相關或常數 
    - ex. add, sub
- 詳情請閱公開說明書 ~或者好好上大二組語~
- [more info](riptutor.com/x86/example/20470/conditional-jumps)

## C Calling Convention
- Stack
	- 一段連續記憶體空間，位址從高長到低
    >一堆盤子
    >只能從最上面的拿
    >加盤子也只能從最上面加	

	- 只對 top 做操作
		- 插入/刪除元素時只能在 esp 插入/刪除
	- 由 esp, ebp 兩個暫存器指向位址之間的記憶體空間
- push 
    - 把值放入 stack (esp)
    - push eax
    - eax 的值會被放入 esp

- pop
	- 把 stack 頂端的值拿出來
	- `pop eax`
	- 把 stack 頂端的值丟出並放入 eax

```c=
void fun1(int var1, int var2){
	int local1 = 1, local2 = 2;
}
```
```assembly=
push var2
push var1
call fun1
add esp, 8
```
## gdb
- gdb filename 用 gdb 把程式打開
- **r**un打成式跑起來，直到第一個中斷點或是程式結束
- **b**reak 設立新斷點
    - break stmbol
    - break *addr
    - break *addr+offset
- info funtion 顯示全部functions
- **n**i 執行下一個指令
- **si** 追進函式內部
- **c**ontinue 繼續跑到下一個斷點
- **disas**semble fun_name 返組譯某函式
- **i**nfo **b**reak 顯示中斷點
- disable/enable breakpoints 停用/啟用中斷點
- **d**elete 清除所有中斷點
    - delete Num 刪除特定中斷點
    - 以 info break 顯示出來的Num為準

- set $reg=目標值
    - set $reg=0x12345678
    - eax=0x12345678
- set *addr=目標值
    - set *0x878787878787=0x12345678
        > 0x878787878787這塊記憶體會記錄0x12345678













---
###### tags: `Enlightened` `NISRA` `2022`

<style>
    .navbar-brand:before {
        content: ' NISRA × ';
        padding-left: 1.7em;
        background-image: url(https://i.imgur.com/ue2XHqP.png);
        background-repeat: no-repeat;
        background-size: contain;
    }
    .navbar-brand > .fa-file-text {
        padding-left: 0.1em;
        display: none;
    }
</style>
