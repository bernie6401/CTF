# Crypto I by ali

:::danger
請愛惜共筆，勿進行惡意刪減
:::

:::info
CTF 平台：class.nisra.net
:::

# 大綱
- 密碼學簡介
- 名詞解釋
- 編碼
- 柯克霍夫原則
- 古典密碼學


## 甚麼是密碼學？
> 羅納德·李維斯特：
> "密碼學是關於如何在敵人存在的環境中通訊"

- 不是研究怎麼安全設密碼
- 不是教你如何破解人家　Facebook
- 不會因為學了密碼學而變成天才駭客
- 很多數學...
    > 不過先不要跑掉！我沒有要教數學
    > 現代密碼學數學比較多
    > 我數學好爛 QQQ by[name=ali]


## 密碼與資訊安全常識
- 使用低強度的密碼比不進行任何加密更危險
- 任何密碼總有一天會被破解 (窮舉)
- 密碼只是資訊安全的一部分

## 名詞介紹
- 加密 Encrypt：
	- 指將明文經過某種程序轉換成密文
- 解密 Decrypt:
    - 指將密文經過某種程序轉換成明文,該程序稱為解密
- 明文 Plaintext:
     - 加密前的訊息
- 密文 Ciphertext:
     - 加密後的訊息

* 演算法
	- 解決複雜問題的程序
* 密碼學演算法:
    - 做與密碼學相關程序(如加密、解密、簽章...)的演算法。
* 金鑰 / 密鑰 Key:
    - 加解密時所使用的「鑰匙」

- 編碼
	- 諮詢從一種形式或格式轉換為另一種形式
- 解碼 Decoding:
    - 編碼的逆過程,即將資料從另一種形式轉換回來。

## Cipher vs Code

- 中文翻譯都是密碼，卻在密碼學中有不同意義
- cipher 有經過加密(某種演算法而形成，具有密鑰)
- code 則是編碼(換一種格式，一旦對照表被盜取，內容不再更新，明文將一覽無遺)
	- 像是棉花糖（Marshmallow vs. cotton candy）
	- 中文一樣但是實際上不是同一種東西

## Lab 00
[解碼器](https://morsecode.world/international/decoder/audio-decoder-adaptive.html)

## 柯克霍夫原則
- 密碼系統即便做不到數學上不可破解，也應在**實際程度**上無法破解
- 即使加密方式公開，只要**密鑰**沒有洩露，密文仍無法破譯。

## 古典密碼學分類
- 古典密碼學
	- 移項式加密
	    - 內容不變，位置改變
		- ex. 密碼棒
		    - 1.由一條加工過、且有夾帶訊息的皮革繞在一個木棒所組成
            - 2.在古希臘，文書記載著斯巴達人用此於軍事上的訊息傳遞
            - 3.密碼接受者需使用一個相同尺寸的棒子讓他將密碼條繞在上面解讀
                - 加密方法
                	- 將要加密的明文分成 N 個一組
                	- 再從上到下抄一遍得到密文
                	- 在將陣列由左至右讀取獲得明文

	- 替換式加密
		- 單表加密
		- 多表加密


## 加密棒
- 由一條加工過、且有夾帶訊息的皮革繞在一個木棒所組成
- 在古希臘，文書記載著斯巴達人用此於軍事上的訊息傳遞
- 密碼接受者需使用一個相同尺寸的棒子讓他將密碼條繞在上面解讀

## 凱撒密碼
- 替換加密
- ex. 偏移量為三
	- A -> D
	- B -> E
- 密碼盤
	- 最早的密碼機械
    - 可以更方便的進行凱撒加解密
	- 內圈為明文，外圈為密文
[密碼盤](https://inventwithpython.com/cipherwheel/)

:::spoiler
LAB 02_b
P1cure_naq_P0qr_v3_5vssrerag

試試看

token:NISRA{flag}

C1pher_and_C0de_i3_5ifferent
:::

## 阿特巴希密碼
- 將字母表整個扭轉：
- 第一個字母 “A” 與最後一個 “Z” 替換
- 第二個 “B” 與倒數第二個 “Y” 替換

> ABCDEFGHIJKLMNOPQRSTUVWXYZ
> ↓↓↓↓↓↓↓↓(向下對照)↓↓↓↓↓↓↓↓↓
> ZYXWVUTSRQPONMLKJIHGFEDCBA

## 簡易替換密碼
- 簡易替換密碼(可以理解為一種建立替換表的方式)

- 傳統上會先把一個關鍵詞寫在字母表最前面，再刪去重複字母，這樣就能得到一個替換表。

- Keyword："HELLO"

> HELLOABCDEFGHIJKLMNOPQRSTUVWXYZ
> HELLOABCDEFGHIJKLMNOPQRSTUVWXYZ
> HELOABCDFGIJKMNPQRSTUVWXYZ

> Keyword："FJCU"

> ABCDEFGHIJKLMNOPQRSTUVWXYZ
> FJCUABDEGHIKLMNOPQRSTVWXYZ
> Keyword："NISRA"

> ABCDEFGHIJKLMNOPQRSTUVWXYZ
> NISRABCDEFGHJKLMOPQTUVWXYZ

- 可以對替換表再進行偏移(凱撒密碼)或翻轉(阿特巴希密碼)

> 下表偏移3
> ABCDEFGHIJKLMNOPQRSTUVWXYZ
> FJCUABDEGHIKLMNOPQRSTVWXYZ
 

> ABCDEFGHIJKLMNOPQRSTUVWXYZ
> XYZFJCUABDEGHIKLMNOPQRSTVW

## 波雷費密碼 Playfair cipher 

- 第一步 對明文進行預處理
	- 預處理規則如下：
    	1.將明文分成兩個字元一組。
        2.若一組內的字母相同，將 "X" 插入兩字母之間，重新分組。
        3.若最後一組剩下一個字，也加入 "X" 

- 第二步 做一個簡易替換密碼
        -先選取一個關鍵字，然後製作一個簡易替換密碼
        -(因為波雷費密碼為5X5的表格，只能容納25個英文字母，故後續的加解密中將 "J" 視為 "I" )
- 第三步 建立5X5的表格
    - "PLAYFIRBCDEGHKMNOQSTUVWXZ"
- 第四步 加密
    - 加密規則：
		- 1.若兩個字元不在同一直行或同一橫列，在矩陣中找出另外兩個字母，使這四個字母成為一個長方形的四個角
		- 2.若兩個字元在同一橫行取這兩個字母右方的字母（若字母在最右方則取最左方的字母）
		- 3.若兩個字元在同一直列取這兩個字母下方的字母（若字母在最下方則取最上方的字母）

## 單表加密攻擊
- 字頻分析
	- 不管是什麼語言，字母都會以固定且可靠的頻率出現。這種現象運用在破解密碼上稱為"字頻分析"
	- 大部分語言中，字母或字符使用的頻率並不是平均的
    - 以英文為例，很明顯母音的使用頻率更高
    - **E**TAOINSHRDLU
    - 這就給了攻擊者可乘之機。因為單表加密只是將字元做替換，所以頻率並不會改變。
    - 如果我們知道一段英文是由單表加密所得。我們對這段英文做字頻分析，發現 ”X” 的出現的頻率最高。那我們合理猜測 ”X” 很有可能替換了 ”E”
### 維吉尼亞密碼
- 1553年由意大利密碼學家發明
- 19世紀誤傳為法國外交官維吉尼亞所創，故稱 “維吉尼亞密碼”
- 我們可以將 “維吉尼亞密碼” 理解為多個 “凱撒密碼”
- 先選擇一個關鍵字，假設"CSIE"，假設要加密的明文為"NISRA"
- 延長關鍵字直到超過明文，對明文以關鍵字母為偏移量，依次進行凱薩加密
- 凱薩密碼加密明文全部依照相同的偏移量，而在維吉尼亞密碼中，每加密一個字母就需做一次凱薩密碼(除非連續兩個相同關鍵字，如"HELLO"之"LL")

[好用小工具](https://gchq.github.io/CyberChef/)
:::spoiler
NISRANI
:::

## 多表加密攻擊
- 兩個文本並排放置，並計算相同字母在兩個文本中出現在相同位置的次數。此計數稱為巧合指數，或簡稱IoC
- 公式 ![](https://i.imgur.com/a92EAaC.png)
- 越無序（IoC越低），越有序（IoC越高）
- 一段完全隨機的文本的IoC會逼近  1  （當文本長度趨近無限）
- 而文本 “越有序” 、 “越不隨機” ，其IoC就會越高
- 字母多的語言，IoC上限更高
- 一段有意義的英語文本，其IoC應接近 1.73
- 巧妙地分組計算IoC，來推得密鑰長度



























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
