# Crypto II by nynapig

:::danger
請愛惜共筆，勿進行惡意刪減
:::

:::info
下午的課程開始前請先在自己的電腦上下載 netcat，或是使用 OS 課程使用的虛擬機
:::

## 古典 vs 現代
- 古典密碼學
    - 以**置換法**為基礎
    - 應用於軍事和情報領域
- 現代密碼學
    - 建立在數學、和通信科學
    - 應用領域廣泛
- 二戰過後電腦發展迅速，開始改加密二進制形式的密碼
    - 以語言學為基礎的加密技術因此失效
- 電腦強大的運算能力讓大部分的古典密碼**不再安全**
- 計算機與電子學的發展能實作更複雜的密碼系統
    - 以語言學為基礎的破密術因此失效

## 訊息安全三要點 CIA

- **C**onfidentiality 機密性
	- 防止未授權的揭露
	- ex. 竊聽違反機密性
- **I**ntegrity 完整性
    - 防止未授權的更改, 最少要能知道被竄改
    - Ex：修改他人訊息違反完整性
- **A**vailability 可用性
    - 確保訊息即時且可靠的被使用
    - EX : 拒絕被訪問違反可用性

> 所有的加密都是能被破解的，並不存在無法破解的加密系統
> 所謂的安全的加密是指破解所需的成本(時間, 電腦硬體等)遠大於可被接受的範圍(例如要算1000年才能破解, 那就是安全的)

## Introduction
- 明文 pt
    - 能直接讀的訊息
    - 要保護的目標
- 密文 ct
    - 加密後的產物
    - 用來傳送
- 金鑰 key
    - 要來加/解密的關鍵
    - 分為公鑰、私鑰
    - 私鑰需要保護好
- 演算法
    - 須公開
    - 用來加/解密的方法
### XOR 互斥或
- 0 XOR 0 = 0
- 0 XOR 1 = 1
- 1 XOR 0 = 1
- 1 XOR 1 = 0

### Min Lab
- 1 xor 0 = 1
- 1 xor 1 = 0
- (1 xor 1) xor 0 = 0
- (0 xor 1) xor 1 = 0 
- (0 xor 1) xor (1 xor 1) = 1
- (0 xor 0) xor (1 xor 1) xor (0 xor 1) = 1

### 模運算 (取餘數)
- 常寫成 mod
    - ${\equiv}$ 同於符號，餘數運算中的等於
- Ex:
    - 8 ${\equiv}$ 2 mod 3, 8/3 = 2餘2
    - 10 ${\equiv}$ 4 mod 6, 10 /6 = 1餘4
    - 11 ${\equiv}$ 1 mod 2, 11/2 = 5餘1
### Min Lab
- 5 ${\equiv}$ x mod 3 
- 12 ${\equiv}$ x mod 5
- 112 ${\equiv}$ x mod 7
- 99 ${\equiv}$ x mod 3
- 87 ${\equiv}$ x mod 11
- 78 ${\equiv}$ x mod 999

:::spoiler 解答
2,2,1,0,10,78
:::

## 對稱式加密


### 共同金鑰
- 加/解密使用同一把金鑰(key)
- 明文(pt) --> key ， 加密演算法 ---> 密文(ct)
- 密文(ct) --> key ， 解密演算法 ---> 明文(pt)

### 區塊加密
- 常用於一直訊息長度的情況
- 將明文分成一塊一塊等長的模組分別加密
- 長度不足通常會 padding 到足夠長度

### 串流加密
- 全部的明文/密文和 key 做加/解密
- 實踐中資料痛常是一個為( bit )並用互斥或 ( xor ) 操作加密

### DES 資料加密系統
#### Background
- 使用DEA
    - Data Encryption Algorithm 資料加密演算法
    - 1974 年 NBS ( 國家標準局，現在的NIST )向公眾徵集可以滿足嚴格設計標準的加密演算法，最終由 IBM 的演算法獲選 
    - DES在1976年11月被定為美國國家標準
- 優點
    - 速度快
    - 可加密大批資料
    - 安全性高

![](https://i.imgur.com/FpelNpH.png)
![](https://i.imgur.com/L2pGmNt.png =300x400)


#### f-Function
- DES主要加密函式四步驟：
    - 1. Expansion E
    - 2. XOR with round key
    - 3. S-box substitution
    - 4. Permutation
![](https://i.imgur.com/l27IwvC.png)




##### Expansion Function E
- 能夠增加更多組合性，提高破解難度
:::spoiler ex
exp_d =[32,1,2,3,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,39,31,32,1]
for i in (0,48)
    out_array[i]=inp_array[exp_d[i]-1]
##i:0~47
:::


##### XOR with round key
- 把 round key (48 bits) 和 擴展函式 E 的 out_array( 48 bits ) 做 XOE 的運算
![](https://i.imgur.com/igFzMT5.png)

##### S-box substitution
- 由八張替換表組成
    - 對於每張表有 6 bits 的 input 和 4 bits 的 output
![](https://i.imgur.com/C1CP8qp.png)

##### Permutation
- 和擴展函式 E 類似的矩陣轉換
    - 轉換的方式一樣只是沒有擴展
    - 32 bits 的輸入，32 bits 的輸出
:::spoiler per
per = [ 16,  7, 20, 21, 29, 12, 28, 17,
         1, 15, 23, 26, 5, 18, 31, 10,
        2,  8, 24, 14,32, 27,  3,  9,
             19, 13, 30,  6, 22, 11,  4, 25 ]
::: 
#### Key Schedule
1. 把 64 bits 的 key 經過一個轉換矩陣 PC-1
2. 分成左右兩邊，再透過位移矩陣做左位移
    左位移: 101 --> 011
3. 左右合併後再用 PC-2 轉換一次，得到 k1
4. 重複 2、3 直到有16把key


#### 使用模式
- Electronic Code Book mod (ECB)
    - ![](https://i.imgur.com/5eubgSa.png) 
- Cipher Block Chaining mode (CBC)
    - ![](https://i.imgur.com/7LTDfr5.png) 
- Output Feedback mod (OFB)
    - ![](https://i.imgur.com/ibWM9sj.png)
- Cipher Feedback mode (CFB)
    - ![](https://i.imgur.com/HJnhrzi.png) 
- Counter mode (CTR)
    - ![](https://i.imgur.com/iZ88oHR.png) 

#### ECB vs CBC
- 在加密時，ECB會保留明文的部分特徵
- 但 CBC 付出的代價是更長的加 / 解密時間
    - 無法同時進行加 / 解密

[CyberChef](https://gchq.github.io/CyberChef/)

### DES面臨的問題

- 56 bits 的金鑰隨著運算能力加強，被暴力破解的可能越來越高
  > 世界上沒有暴力不能解決的問題
  > 如果有
  > 就更暴力
  > [name=nynapig]
- DES 的運作原理過於神奇，無法解釋的神奇
    - S boxs 讓人懷疑背後是否有後門的存在
- 當時的徵選是非公開的
    - 只有 NBS 和 IBM 參與，並沒有其他單位監督
    > 黑箱

#### 如何解決？

- 對於過短的金鑰：
    - 3DES：做三層的DES來達到加長金鑰的效果
    - 重新生一個新的演算法啊
- 對於是否有後門：
    - 重新生一個新的演算法啊
      > 論為什麼要有弟弟妹妹 
      > 因為原本的不行了 所以要有新的，~~重練新號~~
      > [name=nynapig]
- 結論：
    - 與其修改不如砍掉重練
    - 2002 年 5 月 26 日 AES 取代 DES 成為聯邦標準


## 非對稱式加密
### 對稱式加密的難題
- 舉個栗子 (chestnut)：
    - 小明要送訊息給小美，他把明文 (pt) 用 key加密成密文 (ct) 後傳給小美，但小美不知道 key，所以小明又把 key 傳給小美，這樣小美就能解密了~
    > 小明把key傳給小美???然後key就被攔截了@@
    > ![Uploading file..._6jj6qwk0v]()

- 金鑰分為公鑰和私鑰
    - ![Uploading file..._rnthb4h3r]()
### RSA 加密演算法

#### Background
- RSA 由在 1977 年由以下三位提出
    - 羅納德·李維斯特（Ron **R**ivest）
    - 阿迪·薩莫爾（Adi **S**hamir）
    - 倫納德·阿德曼（Leonard **A**dleman）
- RSA 就是他們三人姓氏開頭字母拼在一起組成的

#### 演算法
- step1 : 選超大質數p、q(大小和安全等級相關)
- step2 : 計算模數 n = p*q
- step3 : 計算歐拉函數 $\varphi$(n) = (p-1) * (q-1)ˋ4ˋ4
- step4 : 選擇公鑰 e(1<e<$\varphi$(n)))互質
     - e 常用65537
- step5 : 計算私鑰 d，滿足e * d ≡ 1(mod $\varphi$(n))
```
歐拉函數：小於這個數字且與這個數字互質的正整數數量，例如：φ(5) = 4
所有質數 n 的歐拉函數值 φ(n) = n - 1，因為比它小的正整數與該質數均互質
歐拉函數為積性函數，亦即若a, b互質時，滿足 φ(ab) = φ(a) * φ(b)
```

    
### 安全性
> 很難暴力拆解質因數
> 因為你不夠暴力
> [name=nynapig]
- 基於超大數值因數分解的數學難題

### problem
- 計算速度緩慢
    - 在 2048 ~ 4096 bits 的模數下做運算要快有點難 
    - 低於 2058 bits 的 RSA 已有被破解紀錄
- 量子電腦的開發
    - 讓 RSA 和運用超大質因數分解的加密演算法碰到瓶頸
    - 補充：[秀爾演算法](https://zh.m.wikipedia.org/zh-tw/%E7%A7%80%E7%88%BE%E6%BC%94%E7%AE%97%E6%B3%95)

#### python 小教室

1. 使用別人寫好的 code: 
    - `from Crypto.Util.number import *`
2. 直接宣告變數：
    - `英文變數名 = 變數值`
    - ex. `n = 69420`

:::spoiler Template:

```
from Crypto.Util.number import *
n = XX
p = XX
q = XX
e = XX
c = XX
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
pt = pow(c, d, n)
print(long_to_bytes(pt).decode())
```

:::


## Diffie–Hellman key exchange

### Background
- 由 Whitfield Diffie 和 Martin Hellman 於 1976 年提出
- 被認為是最早的公鑰演算法
- 用於交換對稱式加密的 key 而不是用於加密
- 後續衍伸出很多加密方法
### 演算法
- 假設Alice跟Bob兩人共用n, g兩數(公開), n是很大的質數, g 是 p 的 原根
```
原根：a, m 互質，若使得 a^d = 1 (mod m) 的最小正整數 d = φ(m) 時，此時的 a 為模 m 的原根
```
- 兩人各選一個數a, b(非公開)其中a,b < p
- 各別計算A(g^a mod p)和B( g^b mod p)傳送給對方
- 計算共同key, B^a mod p 和 A^b mod p 其結果會相同
- 用共同key進行對稱式加密

### 安全性
- 基於離散對數(Discrete logarithm)的數學難題
    - 結合同餘運算和原根的一種對數運算(聽起來很邪門)
    - 和質因數分解一樣，目前並沒有已知的快速算法
    - 補充：[大步小步算法](https://zh.wikipedia.org/wiki/%E5%A4%A7%E6%AD%A5%E5%B0%8F%E6%AD%A5%E7%AE%97%E6%B3%95)，時間複雜度O($\sqrt m$)，m 為要拿來 mod 的數字



## 雜湊／哈希函數 Hashing function
- **非加密!!!**
- 主要將不規則長度訊息的輸入，演算成固定長度雜湊的輸出
- 須盡量符合 3 條件：
    - 不可逆
    - 抗碰撞
    - 雪崩效應
- 常見應用
    - 保護資料庫內的密碼
    - 數位簽章
    - 資料完整性的驗證
    - 資料快速查詢
- 常見雜湊
    - MD4
    - MD5
    - SHA-1
    - SHA-256
    - SHA-512

## 數位簽章 digital signature
- 為何需要數位簽章
    - 人們常常會透過簽名的方式來驗證身分等等,但在網路的世界中無法透過紙本簽名的方式,使用公鑰演算法來驗證身分的數位簽章就被發明出來了, 往往有兩種運算, 一個用於簽名，另一個用於驗證
- 常見功能
    - 保障訊息傳輸的完整性
    - 網路上的身分驗證
    - 防止契約抵賴的問題
- 簽章的合法性
    1.表示同意
    2.數位資料
    3.加密技術
    4.憑證機構
    5.憑證效力
### 非對稱式簽章
- RSA 簽章演算法
    - 將訊息經過雜湊函數計算後，再經過 RSA 加密
    - 可得到數位簽章的簽署碼
    - 接收端將此數位簽章碼解密後（公開鑰匙）
    - 再與接收到的訊息所計算出的雜湊值比較
- 簽章：明文 + 私鑰 = 簽名
- 驗章：明文 + 簽名 + 公鑰 = 正確/錯誤
- 如何驗證公鑰的正確性
    - 使用有公信力的第三方憑證機構來做公鑰驗證
    > 很難偽造 
    - 第三方憑證機構（Certificate Authority，簡稱CA）
    - CA透過數位簽章的方式認證公鑰持有者的身分






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
