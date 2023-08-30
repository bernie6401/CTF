# Web I by DU

:::danger
請愛惜共筆，勿進行惡意刪減
:::
:::success
課前可先下載sublime：https://www.sublimetext.com/
:::
:::success
[簡報](https://slides.com/d/WoO21sY/live)
:::
## what is web

- 全球資訊網 **W**orld **W**ide **W**eb
- Web Security

## 課程內容
- 怎麼看到一個網頁
    - URL、HTTP 協定、Server
- cookies
- robots.txt
- 網頁三兄弟（HTML、CSS、JavaScript）
    > 下午的 XSS 非常有趣，推薦大家一定要聽
    > 絕對沒有給下午的講師壓力 owO <!--我要怒你-->
    > [name=Du]

## 怎麼看到一個網頁
- 網路的世界並沒有跳脫世界的規則
    - 一樣要知道他的位置(URL、統一資料定位符)
        > 類似經緯度
	- 一樣需要知道他長怎樣（HTML、超文本標記語言）
    - 一樣需要知道怎麼拿回來(HTTP、超文本傳輸協議)

## what is URl
- 統一資料定位符（Uniform Resource Locator）
> 網址

- 格式:
    - \[協定類型\]:\[伺服器位置\]:\[埠號\]/\[檔案路徑\]?\[查詢\]\#\[片段id\]
- 範例:
    - https://nisra.net:443/tmp/test.php?q=1#1
    >假的
	- 靜態網站
		- 不具備互動功能（會員登入...）
        - ex: 會員購物車
    - 動態網站
		- 會跟使用者產生互動
        - 查詢功能
    - :::spoiler 差別？
       -  靜態跟動態的區別其實並沒有特別的官方定義，不過依照一般的大眾定義來講，只要是能夠跟使用者互動的（比如使用者按一個按鈕，然後畫面上會出現一隻貓貓）這樣的就算是動態網頁，一般的靜態網頁就是你點進去只能看，然後其他操作都沒有。所以一般有 js 的，然後 js 是有內容的話，通常都會是動態網頁
        - 更準確來說應該是有沒有跟伺服器互動，如果那隻貓貓是網頁實時向伺服器要的那就是動態，如果是一開始就跟網頁一起傳過來、然後用本地 JS 去判斷該顯示哪隻喵就是靜態

## what is HTTP
- 超文本傳輸協定（HyperText Transfer Protocol）
    > 用來做網頁前端與後端溝通
- 一種用來傳輸超媒體文件(like HTML)的應用層協定
- 特性：無狀態協定
	- 請求後不會在伺服器保留狀態
    - 前後請求不具關連性

- 所以怎麼請求(Request)

|   方式   |                 說明                  |
|:--------:|:------------------------------------:|
|   GET    |             取得目標資源              |
|   HEAD   |               取得標頭               |
|   POST   |          提交指定資源的實體            |
|   PUT    |      替換目標資源，更新目標資源         |
| CONNECT  |  和指定資源標明的伺服器之間，建立隧道     |
|  DELETE  |             刪除目標資源              |
| OPTIONS  |           取得資源通訊方式             |
|  TRACE   |            用於測試或診斷              |
<!-- 強迫症會發作ㄟ -->

## GET

- 可以想像成是要向網頁查詢資料
- 方式是透過告訴伺服器你需要的資料相關參數
- 格式
	- 網址?參數名稱1=參數內容1&參數名稱2=參數內容2
	> 多個參數使用 & 去做間隔
- 就像寫明信片
    > 缺點 網址會有最大長度 [IE:2083](https://support.microsoft.com/zh-tw/topic/internet-explorer-%E4%B8%AD-url-%E9%95%B7%E5%BA%A6%E4%B8%8A%E9%99%90%E7%82%BA-2-083-%E5%80%8B%E5%AD%97%E5%85%83-174e7c8a-6666-f4e0-6fd6-908b53c12246)
    > 提供資訊會直接裸露在網址內容
- 如果今天傳送的東西是密碼呢?
    - https://nisra.net/login?username=admin&password=root
    - ~~裸奔~~ 
## POST

- 將資料放在 message-body 進行傳送
    - 可以想成把資料寫在一張紙上，再塞進信封內在送
- 傳遞上比較安全且傳遞的資訊可以比較多
    - 彈性也比較高
- 封包攔截仍然能查詢到相關資訊
    >至少不是裸奔


## HTTP 狀態碼


| 狀態碼 |    說明     |
|:------:|:----------:|
|  1xx   |  訊息提示  |
|  2xx   |  請求成功  |
|  3xx   |  重新導向  |
|  4xx   | 用戶端錯誤 |
|  5xx   | 伺服器錯誤 |

## HTTP vs. HTTPS
- HTTP
    - 明文傳輸
    - 就是裸奔
- HTTPS
    - https = http + SSL/TLS
    - 內容加密、身分驗證、數據完整...

## server
- Server運作的作業系統
- 負責接收處理 HTTP 協定的 HTTP Server
- 負責邏輯判斷的後段程式語言
- 負責儲存結構化資料的資料庫


## cookies
- 紀錄使用者狀態資料
	- ex. 網購的購物車
	- 類似便條紙
- 儲存在用戶端
> :::spoiler 登入時的「記住我」
	> 記憶體 cookies：關閉瀏覽器就不見(AKA:非持久性)
	> 硬碟 cookies :儲存於硬體當中，除非使用者刪除，否則將永遠儲存在硬體中(AKA:持久性)
- Cookie 安全嗎？
    - 會被攔截偽造修改
    - 有管理者cookie就可以變成管理者
## Session
- :::spoiler 把資料存在Server
    - 把含有session id 的cookie發送給伺服器，再由伺服器查詢相對應的session id身份
    - 認證不認人
- 透過 session ID 跟 Server 要資料
> 如何避免被竊取
> 透過 HTTPS 連線以避免被外洩，並加上時效性

## robots.txt
- 網站根目錄下的文字檔
- 控管搜索引擎可存取的檔案
	- 放一些機密資料，讓爬蟲爬不到
	> Disallow：爬蟲基本上就爬不到
- 並非絕對標準,而是大家習慣的用法 
- 不希望被看到，就不會被看到嗎？
    > 惡意使用者可以看到 Disallow，就是一個攻擊面向
    > 此地無銀三百兩

### robots.txt的問題
- 可以看到 disallow
>User-agent:*
>Disallow:/you_will_nver_nver_see_me
- :::spoiler  避免方法
    > User-agent: *
    > Disallow:/you_will_never
    > 路徑匹配，間接防止惡意使用者查到原本網址本身

### 老師補充
- 現象=>原理
- 術語的闡述不同

### 前端與後端
    使用者->前端
        1.使用者留言
    前端->後端
        2.把留言丟給後端儲存
    後端->前端
        3.把留言傳回前端
    前端->使用者
        4.資料放上網頁

## 網頁三兄弟

### HTML
- :::spoiler 網頁架構
    - 骨架
- .html
- 超文本標記語言
- 讓瀏覽器讀取
- 是標記語言**not programming language**
    > 各位現在在打得 94 一種標記語言
```html= 
<!DOCTYPE html>
<html>
<head>
	<title></title> <!-- 分頁標題-->
</head>
<body>
	<p>Hello World!</p>
	<!-- This is a comment -->
</body>
</html>
```
#### 常用標籤
- 標籤基本上是成雙成對的出現
- `<!DOCTYPE html>`
    - 讓瀏覽器以 HTML5 渲染
- `<head></head>`
    - 給瀏覽器看得或是導入外掛和文件
- `<title></title>`
    - 網頁的標題
- `<body></body>`
    - 主要部分
- `<!-- This is comment -->`
    - 註解
- `<div></div>`
    - 獨立區塊
    
- `<h1></h1>` ... `<h6></h6>`
    - 標題大小(h1最大，h6最小)
- `<br>` `</br>`
	- 換行
	- 可以單獨存在

- `<img src="圖片網址" alt="替代文字" width=""  height="">`
    - 插入圖片
    > alt="替代文字" 為圖片顯示不出來時的替代文字
- `<a href="網址" target="_blank">文字</a>`
    - 超連結
    > target="_blank" 為在新分頁開啟連結
    - 段落
    > <p>
    > 前後會空一行
    
</p>

#### 文字效果標籤
- `<b></b>`
    - <b>粗體</b>
- `<i></i>`、`<em></em>`
    - <i>斜體</i>
- `<u></u>`
    - <u>底線</u>

#### Attribute 屬性
- 用來敘述元素的相關性質

- class
	- 用來命名，方便 CSS 與 JS 來選取特定的元素
	- 類似於身分（學生、老師），可以有多個元素是同一個 class
- id
	- 一個元素可以有多個class但只能有一個id

##### 常用標籤
- `<img src="圖片網址" alt="替代文字" width="" height="">`
	- 當圖片顯示不出來的時候就會顯示替代文字
- `<a href="網址" target="_blank">文字</a>`
	- 超連結
	- target：在指定的地方開啟連結
    - _blank：在新窗口開啟連結

 ```HTML=
<img src="圖片網址" alt="替代文字" width=""  height="">
插入圖片
<a href="網址" target="_blank">文字</a>
超連結
```
#### 列表
- 無序列表
    - Coffee
    - Milk
```html=
<ul> 
    <li> Coffee </li> 
    <li> Milk </li> 
</ul> 
```
- 有序列表
	1. Coffee
    2. Milk
```html=
<ol> 
    <li> Coffee </li> 
    <li> Milk </li> 
</ol>
```

#### 表單
- `<form action="" method=""></form>`
	- 建立表單
    - `action`
        - 指定發送到伺服器網址，空白表示自己url
    - `method`
		- 指定傳輸時要用哪種方式(HTTP method)
- `<input type="" value="顯示的文字" name="" >`
	- type：text, password, button......
	- `<input type="button"  value="顯示的文字"  onclick="動作"  >`
```html=
<form>
	<input type="text" name="account">
	<input type="password" name="password">
    <input type="button" value="Submit" name="btn">
</form>
```
`<input type="button"  value="顯示的文字"  onclick="動作"  >`
- [input 更多玩法](https://www.fooish.com/html/input-tag.html)

- name和id差在哪邊
    >name用在GET伺服器取得參數
    >id用在js或css操作
- Submit按下去怎麼沒反應
    >因為type 為button,需要自己去定義



### CSS
- Cascading Style Sheets
- 要記得打分號（單個時不打依舊能用但不太好）
- :::spoiler 網頁外觀
    
    - 外表衣服美妝品
  :::
- .css
- inline style
- `<h2 style="color:red;">Red Text</h2>`
	- 寫在裡面
- external style
	
```html=
<head>
    <link rel="stylesheet" type="text/css" href="./css/XXX.css">
</head>
```
```css=
body {
    background: black;
}
```
- selector
	- 負責找尋特定元素
	- html中寫css 必須用\<style\>\</style\>包圍(inner style)
```css=
<style type="text/css">
    body {
        background-color: black;
        /* body tag 中的背景會變黑 */
    }
 
    .class-name {
        color: red;
        /* class-name 中的文字會變紅 */
    }
 
    #id-name {
        color: blue;
        /* id-name 中的文字會變藍 */
    }
</style>
```
- 常見 CSS
	- color : 文字顏色
	    - rgb(255,255,255)
	    - hsl(0,100%.50%)
	- text-align：文字對齊（center, left, right...）
	- font-size：文字大小
	    - px 絕對單位 瀏覽器預設16 px
	    - em 相對單位 每個子元素*父元素的相對大小
    - background-color : 背景顏色
    - background-img: url("圖片網址")
    - [google (css property)](https://www.google.com/search?q=css+property&rlz=1C5CHFA_enTW729TW729&oq=css+property&aqs=chrome..69i57j69i64.1144j0j7&sourceid=chrome&ie=UTF-8)


### JS
- :::spoiler 網頁功能
    - 皮膚肌肉血液
- .js
- 高階直譯式語言
- **不是JAVA**

#### 寫在哪
- 寫在 HTML 裡
- 另外寫一個 .js 檔

#### 宣告變數
- ```var num = 666;```
	- 數字
- ```var str="666"// or '666';```
    - 字串
- ```var arr = \[123 "apple"\];```
    - 陣列
    - 可以把它想像成是一疊的盒子
    - ex: 取index 0: arr[0]
- ```var bool = true // or false;```
    - 布林

#### 運算子
- `+ - * /`
- `==, !=, >, >=, <, <=`
- `&& , ||`
- `%` 取餘數 ex. 5%3=2
- `**` 次方
- `===, !==` 嚴格比較
    - 除了比較值還比較型態


#### 自訂函數
```javascript=
<script>
	function add(x,y){
    	return x+y ;
    }
</script>
```

#### 註解(comment)
- 單行註解以 `//` 開頭
- 多行註解以 ``/*`` 開頭，以 ``*/`` 結尾

#### 輸出
- `console.log()`
    - F12 開發者工具->Console顯示
- `alert()`
    - 彈出視窗顯示

#### DOM 文件物件模型
- Document Object Model
- 抓取元素
- 
##### DOM 文件物件模型
- 操作
```javascript=
    document.getElementById("id-name");
    document.getElementByClassName("class-name");
    document.getElementByTagName("tag-name");
```
```javascript=
var test = document.getElementById("id-name");
// 用 test 去接物件
var value = test.value;

 
test.innerText = "I've been changed"
// 最常使用，獲取或設置元素內的文字
test.innerHTML
// 獲取或設置元素包含的 HTML 標籤
```


```javascript=
function Get_Date(){
    document.getElementById('time').innerText = Date();
}

```

:::spoiler lab answer
```html=


<script type="text/javascript">
	

function call(){
	var height = document.getElementById("height").value;
	var weight = document.getElementById("weight").value;
	var BMI =weight/ (height*0.01^2);
	alert(BMI);
}


</script>


	身高：<input id="height" type="text" value="168">
	<br>
	體重：<input id="weight" type="text" value="65">
	<br>

	<input type="button" value="Submit" name="btn" id="submit" onclick="call()">
```
:::spoiler 另一種寫法
```javascript=
addEventListener(
'click',function(){
blahblahblah....

})
```


[extra lab](https://drive.google.com/file/d/1Y_3-tg5bMp46fYois6BYAFSI68MfZjBw/view)

### CSRF
- 跨站請求偽造（Cross Site Request Forgery）
- 讓使用者發出惡意請求




<!-- 共筆歡迎大家>< -->
<!--好耶-->
<!-- 你好啊 ~ 歡迎加入共筆 -->
<!-- Magus was here -->
<!-- hello minasun -->






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
