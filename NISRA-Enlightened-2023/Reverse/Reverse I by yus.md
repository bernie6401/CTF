# Reverse I by yus

:::danger
請愛惜共筆，勿進行惡意刪減
:::
:::info
上午的課程開始前請先在自己的電腦上下載 netcat，或是使用 OS 課程使用的虛擬機
:::
## Reverse?
- 逆向工程
- 把執行檔盡可能的還原成原始碼，來達成分析演算法、挖掘程式漏洞等目的
>今天的內容會偏硬
>[name=yus]

## 為什麼學 C
### 維基百科會告訴你
- 高效
- 靈活
- 跨平台
- 功能豐富
- 表達力強
- 較高的可移植性 *
>不同平台會有不同的 API
>=> Windows 的 C code 不太能無痛移植到任何地方
>ex. 剪貼版 Clipboard

### 駭客會告訴你
- 可以直接操作記憶體
- 編譯出來的執行檔體積小
- 病毒幾乎都是 C 
  >甚至是組合語言(好東西
- ...
- TL;DR: C 就是簡單粗暴有效
## 了解 C 之前...
- bits/bytes
- 資料型態
### bits/bytes
- bits：**bi**nary digi**t**s
    - 電腦只會看 0 跟 1
    - 每一個 '0' 跟每一個 '1' 就是一個 bit
    - Bytes：1 byte = 8 bits
- Bytes: 1 byte = 8 bits

- bits/bytes
    - 最早使用 1 Byte 來表達一個字母（字元）[維基百科](https://zh.wikipedia.org/zh-tw/%E5%AD%97%E8%8A%82)
    - 26 個英文字母
        - 需要 5 bits 儲存
    - 26 小寫字母 + 26 大寫字母 + 10 阿拉伯數字 = 63
        - 需要 6 bits 儲存
    - 6 bits ？8 bits？
        - 符合實用且約定俗成

###  32/64 bit?
- 跟暫存器大小有關
    - 32 bit 電腦 : 32 bit 大小的暫存器
    - 64 bit 同理
- TL;DR :可先簡單理解成電腦能一次處理的、資料的最小單位
    > 詳情下午見

## 資料型態

> 一個很大的前提
> - 電腦只認 0/1
> - 所有資料都是數字衍伸的
>   常以 Hex (16進位顯示)

- 在電腦中常以 16 進位 Hex 顯示
    - ex. 0xA
        - 0x：表示後面是 16 進位
        - A：16 進位中 10（十進位） 的表示方法`
### 整數
- 分為有號數 Signed 、無號數 Unsigned
- Sign and Magnitude：第一位代表正~0~負~1~數
- 2's complement：Sign and Magnitude 的反轉 + 1

### 浮點數(小數)
|Sign|Exponent|Mantissa|
|--|--|--|
|1 bit |8 bits |23 bits|

[線上工具](https://www.h-schmidt.net/FloatConverter/IEEE754.html)

### 字元
- 說白了就是英文字母，每個字母都有一個數字來代表
- ASCII table

### 小結
- 為什麼選擇 C
- bit/byte
    - 進位
- 資料型態
    - 整數
        - 無號數 → unsigned int
        - 有號數 → int
    - 浮點數 → float
    - 字元字串 → char


<!-- -->



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
