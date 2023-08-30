# Misc by LAVI

:::danger
請愛惜共筆，勿進行惡意刪減
:::

## 資安常識 & 意識
- 講到資安會想到什麼？
    - 密碼、外流、駭客......
- [Insecam](http://www.insecam.org/)
- 撞庫攻擊
    - 攻擊者使用外洩密碼撞其他帳號
	- 不同平台最好使用不同密碼
- [';--have i been pwned](https://haveibeenpwned.com/)
> "Have I Been Pwned" or " Firefox Monitor"不會蒐集email資訊
> who's been pwned 可以查詢資料主要來源
- chrome 使用**明文**紀錄密碼

## 什麼是駭客
- 白帽駭客
	- 促進資安社群的發展
- 灰帽
	- 雙面人
- 黑帽
	- 違法分子

## CTF Intro
- **C**apture **T**he **F**lag
	- Jeopardy
		- Reverse
		- Web
		- Pwn
		- Crypto
		- Forensic
		- Misc
	- Attack & Defense
    - King of the Hill
- Flag
	- Flag General Format
		- < CTF name >{...}
    - [Leet](https://zh.wikipedia.org/wiki/Leet)
        - Enlightened_2022_Welcome
        - 3nl19H73n3D_2022_w3lC0M3
- [Enlightened Class ctfd 平台](https://class.nisra.net/)
- token:``NISRA{w3lc0me_4o_2O22N15Ra_3n1ight3ned_cl4ss}``
## Misc
- **Misc**ellaneous
- 領域分支
	- Recon 訊息蒐集
	- Encode 編碼
	- Stego 隱寫
	- Forensic 鑑識
### Recon
- 社交工程
	- ex. 穿反光背心就能偽裝成工作人員成功逃票
- Google Hacking 
	- 透過特殊語法搜尋
		- 機敏資料、文件
		- 有漏洞的網頁、程式碼
		- [Google Hacking Database](https://www.exploit-db.com/google-hacking-database)
	- Operators
		- inurl
		    - 在 url 找指定關鍵字
		- intext
			- 網頁中的關鍵字
		- intitle
			- 網頁標題
		- filetype
			- 找出檔案類型
			- ex. pdf, txt...
			- 找原文書的幫手
		- site
		    - 特定網站搜尋特定內容

- [Wayback Machine](https://archive.org/web/)
	- 查詢過去有被記錄的網頁

### Encode
- ASCII
	- **A**merican **S**tandard **C**ode for **I**nformation **I**nterchange
	- 電腦常用編碼系統
		- 128 個字元
        - "A" = 65
		- "a" = 97
		- "0" = 48
- Binary
	- {0,1,2,3,4,5,6,7,8,9} -> {0,1}
	- (87)~10~  = = (1010111)~2~
	- 1 * 2^6^ + 0 * 2^5^ + 1 * 2^4^ + 0 * 2^3^ + 1 * 2^2^ + 1 * 2^1^ + 1 * 2^0^
    - (11011010)~2~ = (?)~10~
		- A: 218
    - 常用於計算機與資料科學
	- [Online Converter](https://www.binaryhexconverter.com/decimal-to-binary-converter)
- base 64
	- **不是加密**是編碼
    - 利用以下這五種種類的字元組合64個字符編碼
		- a~z, A~Z, 0~9, +, /
	- [base 64 Online Converter](https://www.base64decode.org/)
    - ASCII -> Base64
        - Ex: A -> QQ== 
### Cyberchef
- [cyberchef](https://gchq.github.io/CyberChef/)
### Steganography
- 安全性 + 隱蔽性 + 藏密量
- 著重隱藏資料
    - 強健性不足
    - 被發現就失去意義
- [StegSolve](http://www.caesum.com/handbook/Stegsolve.jar)
    - 圖片隱寫解題神器
- [Magic Eye](https://magiceye.ecksdee.co.uk/)
- 立體視覺圖
	- 2D 圖創造出 3D 效果
- Pixel
    - **Pix**(picture) + **El**ement 
	- 點陣圖
	- RGB(+ Alpha)
		- Alpha, 增加了透明度
### Frame Browser
- 觀察動圖
	- 分析每幀的畫面
	- 常見動圖格式：GIF
### Image Combiner
- 合併兩張圖
	- XOR、AND、SUB、MUL......
	- 混合位元運算、pixel、RGB 的觀念
- Operator
	- NOT(')
		- 
	- AND(o)
		- 1。1 = 1
		- 0。1 = 1。0 = 0。0 = 0
	- OR(+)
		- 1+1 = 0+1 = 1+0 = 1
		- 0+0 = 0
- RGB
	- **R**ed、 **G**reen、 **B**lue
	- Bin, Dec, Hex, 百分比
	- 3 bytes = 3 * 8 bits(0~255)
		- True color

## Data Extract
- 按照特定方式、順序提取圖片資訊
- [Bit plane](https://en.wikipedia.org/wiki/Bit_plane)


### LSB
- **L**east **S**ignificant **B**it
- 2^8^ * 2^8^ * 2^8^ = 16,777,216 種顏色
	- 人眼無法察覺細微變化
	- 權重降低
	- 影響降低
	- [LSB&演算法](http://ir.lib.pccu.edu.tw/retrieve/47927/129-3gsweb.pdf)



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
